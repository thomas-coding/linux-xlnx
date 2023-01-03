// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018-2019 Francois Beerten
 */


#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/idr.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/sched/signal.h>
#ifdef CONFIG_X86
#include <asm/set_memory.h>
#endif

#define DRIVER_NAME "slxidmem"
#define SLXI_DMEM_MAX_DEVICES         (1U << MINORBITS)

#if  ( LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0) )
#define POLLT unsigned int
#else
/* since afc9a42b7464f76e1388cad87d8543c69f6f74ed, uses __poll_t */
#define POLLT __poll_t
#endif

#if  ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0) )
/* Since 5.0, dma_alloc_coherent replaces dma_zalloc_coherent.*/
#define dma_zalloc_coherent dma_alloc_coherent
#endif

struct slxidmem_dev {
	struct device *dev;
	char __iomem *regs;
	resource_size_t regsphys;
	struct cdev cdev;
	struct mutex lock;
	int minor;
	atomic_t ready_count;
	wait_queue_head_t irqwait;
	int irqno;
};

struct slxidmem_user {
	struct slxidmem_dev *sidev;
	dma_addr_t dmamem;
	char *vdmamem;
	size_t dmamemsz;
	s32 event_count;
};

static struct class *slxidmem_class;
static int slxidmem_major;
static DEFINE_IDA(minors);

static int slxidmem_open(struct inode *inode, struct file *filep)
{
	struct slxidmem_dev *sidev;
	struct slxidmem_user *user;
	int ret = 0;

	sidev = container_of(inode->i_cdev, struct slxidmem_dev, cdev);
	if (!sidev)
		return -ENODEV;

	get_device(sidev->dev);

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		ret = -ENOMEM;
		goto err_alloc_user;
	}
	user->sidev = sidev;
	atomic_set(&sidev->ready_count, 0);
	user->dmamemsz = 0;
	user->event_count = 0;
	filep->private_data = user;

	return 0;

err_alloc_user:
	put_device(sidev->dev);
	return ret;
}

static int slxidmem_fasync(int fd, struct file *filep, int on)
{
	return -EINVAL;
}

static void slxidmem_free_dmamem(struct slxidmem_dev *sidev,
	struct slxidmem_user *user)
{
	dma_free_coherent(sidev->dev, user->dmamemsz,
				  user->vdmamem, user->dmamem);
	user->vdmamem = NULL;
}

static int slxidmem_release(struct inode *inode, struct file *filep)
{
	int ret = 0;
	struct slxidmem_user *user = filep->private_data;
	struct slxidmem_dev *sidev = user->sidev;

	if (user->vdmamem)
		slxidmem_free_dmamem(sidev, user);
	kfree(user);
	put_device(sidev->dev);
	return ret;
}


static POLLT slxidmem_poll(struct file *filep, poll_table *p)
{
	struct slxidmem_user *user = filep->private_data;
	struct slxidmem_dev *sidev = user->sidev;

	/* WARNING: Interrupts are disabled in slxidmem_irq().*/
	poll_wait(filep, &sidev->irqwait, p);
	if (user->event_count != atomic_read(&sidev->ready_count))
		return POLLIN | POLLRDNORM;
	return 0;
}


static ssize_t slxidmem_read(struct file *filep, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct slxidmem_user *user = filep->private_data;
	struct slxidmem_dev *sidev = user->sidev;
	ssize_t r;

	if (*ppos == 0) {
		if (count < sizeof(user->dmamem) || copy_to_user(buf, &user->dmamem, sizeof(user->dmamem))) {
			r = -EFAULT;
		} else {
			r = sizeof(user->dmamem);
			*ppos += r;
		}
		return r;
	} else {
		DECLARE_WAITQUEUE(wait, current);
		s32 event_count;

		enable_irq(sidev->irqno);

		if (count != sizeof(event_count))
			return -EINVAL;

		add_wait_queue(&sidev->irqwait, &wait);

		do {
			set_current_state(TASK_INTERRUPTIBLE);

			event_count = atomic_read(&sidev->ready_count);
			if (event_count != user->event_count) {
				__set_current_state(TASK_RUNNING);
				if (copy_to_user(buf, &event_count, count))
					r = -EFAULT;
				else {
					user->event_count = event_count;
					r = count;
				}
				break;
			}

			if (filep->f_flags & O_NONBLOCK) {
				r = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				r = -ERESTARTSYS;
				break;
			}
			schedule();
		} while (1);

		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&sidev->irqwait, &wait);

		return r;
	}
}

static ssize_t slxidmem_write(struct file *filep, const char __user *buf,
			size_t count, loff_t *ppos)
{
	return -EINVAL;
}

static const struct vm_operations_struct slxidmem_physical_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int slxidmem_mmap_regs(struct vm_area_struct *vma)
{
	struct slxidmem_user *user = vma->vm_private_data;
	struct slxidmem_dev *sidev = user->sidev;

	vma->vm_ops = &slxidmem_physical_vm_ops;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return io_remap_pfn_range(vma,
		vma->vm_start,
		(sidev->regsphys) >> PAGE_SHIFT,
		vma->vm_end - vma->vm_start,
		vma->vm_page_prot);
}

static int mmap_dmamem(struct vm_area_struct *vma,
	struct slxidmem_dev *sidev, void *addr,
	dma_addr_t phys, off_t offset, size_t sz)
{
	unsigned long pgoff = vma->vm_pgoff;
	unsigned long vmstart = vma->vm_start;
	int r;

	/* Here vm_pgoff has a fake offset to tell which mapping to do.
	 * Unfortunately, dma_mmap_coherent() does not take an explicit offset
	 * argument. Force it in vma temporarily to 0 to make sure
	 * dma_mmap_coherent() maps the buffer from the beginning. */
	vma->vm_pgoff = 0;
	vma->vm_start = vmstart + offset;
	vma->vm_end = vma->vm_start + sz;
#ifdef CONFIG_X86
	set_memory_uc((unsigned long)addr, sz >> PAGE_SHIFT);
#endif
	r = dma_mmap_coherent(sidev->dev, vma,
		addr, phys, sz);
	vma->vm_pgoff = pgoff;
	vma->vm_start = vmstart;

	return r;
}

static int slxidmem_mmap_dmamem(struct vm_area_struct *vma)
{
	struct slxidmem_user *user = vma->vm_private_data;
	struct slxidmem_dev *sidev = user->sidev;
	int requested_pages;
	int r;

	requested_pages = vma_pages(vma);
	if (user->vdmamem)
		/* Mapping already done */
		return -EINVAL;
	user->dmamemsz = requested_pages * PAGE_SIZE;
	user->vdmamem = dma_zalloc_coherent(sidev->dev, user->dmamemsz,
					 &user->dmamem, GFP_KERNEL);
	r = -ENOMEM;
	if (!user->vdmamem)
		goto allocfailed;

	vma->vm_ops = &slxidmem_physical_vm_ops;

	r = mmap_dmamem(vma, sidev, user->vdmamem, user->dmamem, 0, user->dmamemsz);
	if (r)
		goto dmammapfailed;
	return r;

dmammapfailed:
	slxidmem_free_dmamem(sidev, user);
	user->dmamemsz = 0;
allocfailed:
	return r;
}

static int slxidmem_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct slxidmem_user *user = filep->private_data;
	int ret = 0;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_private_data = user;

	switch (vma->vm_pgoff) {
		case 0:
			ret = slxidmem_mmap_regs(vma);
			break;
		case 1:
			ret = slxidmem_mmap_dmamem(vma);
			break;
		default:
			ret = -EINVAL;
	}

	return ret;
}


static const struct file_operations slxidmem_fops = {
	.owner          = THIS_MODULE,
	.open           = slxidmem_open,
	.release        = slxidmem_release,
	.read           = slxidmem_read,
	.write          = slxidmem_write,
	.mmap           = slxidmem_mmap,
	.poll           = slxidmem_poll,
	.fasync         = slxidmem_fasync,
	.llseek         = no_llseek,
};

static irqreturn_t slxidmem_irq(int irq, void *d)
{
	struct slxidmem_dev *sidev = (struct slxidmem_dev *)d;

	disable_irq_nosync(irq);
	atomic_inc(&sidev->ready_count);
	wake_up_interruptible(&sidev->irqwait);

	return IRQ_HANDLED;
}


static int slxidmem_create_device(struct slxidmem_dev *sidev,
	struct device *dev, int irq)
{
	int r;

	r = devm_request_irq(dev, irq, slxidmem_irq, 0,
		"slxidmem", sidev);
	sidev->irqno = irq;

	sidev->minor = ida_simple_get(&minors, 0, SLXI_DMEM_MAX_DEVICES,
		GFP_KERNEL);
	if (sidev->minor < 0) {
		dev_err(dev, "could not allocate minor for device\n");
		return sidev->minor;
	}
	mutex_init(&sidev->lock);
	init_waitqueue_head(&sidev->irqwait);

	if (IS_ERR(device_create(slxidmem_class, dev,
				 MKDEV(slxidmem_major, sidev->minor), NULL,
				 "slxidmem%u", sidev->minor))) {
		dev_err(dev, "can't create device\n");
		r = -ENODEV;
		goto faildevcreate;
	}

	cdev_init(&sidev->cdev, &slxidmem_fops);
	sidev->cdev.owner = THIS_MODULE;
	r = cdev_add(&sidev->cdev, MKDEV(slxidmem_major, sidev->minor), 1);
	if (r)
		goto failcdevadd;
	return 0;

failcdevadd:
	dev_err(dev, "chardev registration failed\n");
	device_destroy(slxidmem_class, MKDEV(slxidmem_major, sidev->minor));
faildevcreate:
	ida_simple_remove(&minors, sidev->minor);

	return r;
}


static int slxidmem_remove_device(struct slxidmem_dev *sidev)
{
	if (!sidev)
		return -ENODEV;

	cdev_del(&sidev->cdev);

	device_destroy(slxidmem_class, MKDEV(slxidmem_major, sidev->minor));
	ida_simple_remove(&minors, sidev->minor);

	return 0;
}

#ifdef CONFIG_OF
static int slxidmem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct slxidmem_dev *sidev;
	struct resource *memres;
	int retval;
	int irq;

	retval = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (retval < 0)
		return retval;

	sidev = devm_kzalloc(dev, sizeof(*sidev), GFP_KERNEL);
	if (!sidev)
		return -ENOMEM;
	sidev->dev = dev;
	memres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	sidev->regs = devm_ioremap_resource(dev, memres);
	if (IS_ERR(sidev->regs))
		return PTR_ERR(sidev->regs);
	sidev->regsphys = memres->start;
	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return -ENODEV;

	platform_set_drvdata(pdev, sidev);

	return slxidmem_create_device(sidev, dev, irq);
}

static int slxidmem_remove(struct platform_device *pdev)
{
	struct slxidmem_dev *sidev = platform_get_drvdata(pdev);

	return slxidmem_remove_device(sidev);
}

static struct of_device_id slxidmem_match[] = {
	{ .compatible = "slxidmem" },
	{ .compatible = "cryptosoc" },
	{ },
};

static struct platform_driver slxidmem_pdrv = {
	.probe = slxidmem_probe,
	.remove = slxidmem_remove,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(slxidmem_match),
	},
};
#endif


static int __init slxidmem_init(void)
{
	int retval;
	dev_t devt;

	slxidmem_class = class_create(THIS_MODULE, "siemul");
	if (IS_ERR(slxidmem_class)) {
		retval = PTR_ERR(slxidmem_class);
		printk(KERN_ERR "can't register class\n");
		goto err;
	}
	retval = alloc_chrdev_region(&devt, 0, SLXI_DMEM_MAX_DEVICES, "siemul");
	if (retval) {
		printk(KERN_ERR  "can't register character device\n");
		goto err_class;
	}
	slxidmem_major = MAJOR(devt);

#ifdef CONFIG_OF
	retval = platform_driver_register(&slxidmem_pdrv);
	if (retval) {
		printk(KERN_ERR  "can't register platform driver\n");
		goto err_unchr;
	}
#endif

	printk("slxidmem Linux Driver, version 0.0.2, init OK\n");

	return 0;
err_unchr:
	unregister_chrdev_region(devt, SLXI_DMEM_MAX_DEVICES);
err_class:
	class_destroy(slxidmem_class);
err:
	return retval;
}

static void __exit slxidmem_exit(void)
{
#ifdef CONFIG_OF
	platform_driver_unregister(&slxidmem_pdrv);
#endif

	unregister_chrdev_region(MKDEV(slxidmem_major, 0), SLXI_DMEM_MAX_DEVICES);

	class_destroy(slxidmem_class);
}

module_init(slxidmem_init);
module_exit(slxidmem_exit);


MODULE_AUTHOR("Francois Beerten");
MODULE_DESCRIPTION("Silex Insight hardware driver with coherent DMA memory");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRIVER_NAME);
