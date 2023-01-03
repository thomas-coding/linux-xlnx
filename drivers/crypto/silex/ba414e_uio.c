/*
 * Userspace I/O driver for Silex Insight BA414 crypto accelerator
 *
 * Copyright (C) 2014-2019 Silex Insight
 * Copyright (C) 2018 François Beerten
 *
 * Inspired by uio_genirq_pdrv by Magnus Damm.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/uio_driver.h>
#include <linux/device.h>
#include <linux/slab.h>

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>

#define DRIVER_NAME "ba414e_uio"

struct ba414_pdrv_platdata {
	struct uio_info *uioinfo;
	struct platform_device *pdev;
};


static irqreturn_t uio_iq_handler(int irq, struct uio_info *info)
{
	return IRQ_HANDLED;
}

static int ba414_probe(struct platform_device *pdev)
{
	struct uio_info *uioinfo = dev_get_platdata(&pdev->dev);
	struct ba414_pdrv_platdata *priv;
	struct uio_mem *uiomem;
	int ret = -EINVAL;
	int i;

	if (pdev->dev.of_node) {
		/* alloc uioinfo for one device */
		uioinfo = devm_kzalloc(&pdev->dev, sizeof(*uioinfo),
				       GFP_KERNEL);
		if (!uioinfo) {
			dev_err(&pdev->dev, "unable to kmalloc\n");
			return -ENOMEM;
		}
		uioinfo->name = pdev->dev.of_node->name;
		uioinfo->version = "devicetree";
		/* Multiple IRQs are not supported */
	}

	if (!uioinfo || !uioinfo->name || !uioinfo->version) {
		dev_err(&pdev->dev, "missing platform_data\n");
		return ret;
	}

	if (uioinfo->handler || uioinfo->irqcontrol ||
	    uioinfo->irq_flags & IRQF_SHARED) {
		dev_err(&pdev->dev, "interrupt configuration error\n");
		return ret;
	}

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev, "unable to kmalloc\n");
		return -ENOMEM;
	}

	priv->uioinfo = uioinfo;
	priv->pdev = pdev;

	if (!uioinfo->irq) {
		ret = platform_get_irq(pdev, 0);
		uioinfo->irq = ret;
		if (ret == -ENXIO && pdev->dev.of_node)
			uioinfo->irq = UIO_IRQ_NONE;
		else if (ret < 0) {
			dev_err(&pdev->dev, "failed to get IRQ\n");
			return ret;
		}
	}

	uiomem = &uioinfo->mem[0];

	for (i = 0; i < pdev->num_resources; ++i) {
		struct resource *r = &pdev->resource[i];

		if (r->flags != IORESOURCE_MEM)
			continue;

		if (uiomem >= &uioinfo->mem[MAX_UIO_MAPS]) {
			dev_warn(&pdev->dev, "device has more than "
					__stringify(MAX_UIO_MAPS)
					" I/O memory resources.\n");
			break;
		}

		uiomem->memtype = UIO_MEM_PHYS;
		uiomem->addr = r->start;
		uiomem->size = resource_size(r);
		uiomem->name = r->name;
		++uiomem;
	}

	while (uiomem < &uioinfo->mem[MAX_UIO_MAPS]) {
		uiomem->size = 0;
		++uiomem;
	}

	uioinfo->handler = uio_iq_handler;
        uioinfo->irq_flags = IRQF_TRIGGER_RISING;
	uioinfo->priv = priv;

	ret = uio_register_device(&pdev->dev, priv->uioinfo);
	if (ret) {
		dev_err(&pdev->dev, "unable to register uio device\n");
		return ret;
	}

	platform_set_drvdata(pdev, priv);
	return 0;
}

static int ba414_remove(struct platform_device *pdev)
{
	struct ba414_pdrv_platdata *priv = platform_get_drvdata(pdev);

	uio_unregister_device(priv->uioinfo);

	return 0;
}

static struct of_device_id ba414_match[] = {
	{ .compatible = "ba414" },
	{ },
};

static struct platform_driver ba414_pdrv = {
	.probe = ba414_probe,
	.remove = ba414_remove,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(ba414_match),
	},
};

module_platform_driver(ba414_pdrv);

MODULE_DESCRIPTION("Silex Insight BA414 asymmetric crypto accelerator");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Silex Insight");
MODULE_ALIAS("platform:" DRIVER_NAME);
