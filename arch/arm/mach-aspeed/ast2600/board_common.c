// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Aspeed Technology Inc.
 */
#include <common.h>
#include <dm.h>
#include <ram.h>
#include <timer.h>
#include <asm/io.h>
#include <asm/arch/timer.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <dm/uclass.h>
#include <asm/arch/scu_ast2600.h>
#include <asm/global_data.h>

DECLARE_GLOBAL_DATA_PTR;

/* Memory Control registers */
#define MCR_BASE			0x1e6e0000
#define MCR_CONF			(MCR_BASE + 0x004)

/* bit fields of MCR_CONF */
#define MCR_CONF_ECC_EN			BIT(7)
#define MCR_CONF_VGA_MEMSZ_MASK		GENMASK(3, 2)
#define MCR_CONF_VGA_MEMSZ_SHIFT	2
#define MCR_CONF_MEMSZ_MASK		GENMASK(1, 0)
#define MCR_CONF_MEMSZ_SHIFT		0

void aspeed_mmc_init(void);

int board_mmc_init(struct bd_info *bis){
	aspeed_mmc_init();
	return 0;
}

int dram_init(void)
{
	int ret;
	struct udevice *dev;
	struct ram_info ram;

	ret = uclass_get_device(UCLASS_RAM, 0, &dev);
	if (ret) {
		debug("cannot get DRAM driver\n");
		return ret;
	}

	ret = ram_get_info(dev, &ram);
	if (ret) {
		debug("cannot get DRAM information\n");
		return ret;
	}

	gd->ram_size = ram.size;
	return 0;
}

int board_init(void)
{
	int i = 0, rc;
	struct udevice *dev;

	gd->bd->bi_boot_params = CONFIG_SYS_SDRAM_BASE + 0x100;

	while (1) {
		rc = uclass_get_device(UCLASS_MISC, i++, &dev);
		if (rc)
			break;
	}

	return 0;
}

void board_add_ram_info(int use_default)
{
	int rc;
	uint32_t conf;
	uint32_t ecc, act_size, vga_rsvd;
	struct udevice *scu_dev;
	struct ast2600_scu *scu;

	rc = uclass_get_device_by_driver(UCLASS_CLK,
					 DM_DRIVER_GET(aspeed_ast2600_scu), &scu_dev);
	if (rc) {
		debug("%s: cannot find SCU device, rc=%d\n", __func__, rc);
		return;
	}

	scu = devfdt_get_addr_ptr(scu_dev);
	if (IS_ERR_OR_NULL(scu)) {
		debug("%s: cannot get SCU address pointer\n", __func__);
		return;
	}

	conf = readl(MCR_CONF);

	ecc = conf & MCR_CONF_ECC_EN;
	act_size = 0x100 << ((conf & MCR_CONF_MEMSZ_MASK) >> MCR_CONF_MEMSZ_SHIFT);
	vga_rsvd = 0x8 << ((conf & MCR_CONF_VGA_MEMSZ_MASK) >> MCR_CONF_VGA_MEMSZ_SHIFT);

	/* no VGA reservation if efuse VGA disable bit is set */
	if (readl(scu->efuse) & SCU_EFUSE_DIS_VGA)
		vga_rsvd = 0;

	printf(" (capacity:%d MiB, VGA:%d MiB), ECC %s", act_size,
	       vga_rsvd, (ecc) ? "on" : "off");
}

void enable_caches(void)
{
	/* get rid of the warning message */
}

union ast2600_pll_reg {
	unsigned int w;
	struct {
		unsigned int m : 13;		/* bit[12:0]	*/
		unsigned int n : 6;		/* bit[18:13]	*/
		unsigned int p : 4;		/* bit[22:19]	*/
		unsigned int off : 1;		/* bit[23]	*/
		unsigned int bypass : 1;	/* bit[24]	*/
		unsigned int reset : 1;		/* bit[25]	*/
		unsigned int reserved : 6;	/* bit[31:26]	*/
	} b;
};

void aspeed_mmc_init(void)
{
	u32 reset_bit;
	u32 clkstop_bit;
	u32 clkin = 25000000;
	u32 pll_reg = 0;
	u32 enableclk_bit;
	u32 rate = 0;
	u32 div = 0;
	u32 i = 0;
	u32 mult;
	u32 clk_sel = readl(0x1e6e2300);

	/* check whether boot from eMMC is enabled */
	if ((readl(0x1e6e2500) & 0x4) == 0)
		return;

	/* disable eMMC boot controller engine */
	*(volatile int *)0x1e6f500C &= ~0x90000000;
	/* set pinctrl for eMMC */
	*(volatile int *)0x1e6e2400 |= 0xff000000;

	/* clock setting for eMMC */
	enableclk_bit = BIT(15);

	reset_bit = BIT(16);
	clkstop_bit = BIT(27);
	writel(reset_bit, 0x1e6e2040);
	udelay(100);
	writel(clkstop_bit, 0x1e6e2084);
	mdelay(10);
	writel(reset_bit, 0x1e6e2044);

	pll_reg = readl(0x1e6e2220);
	if (pll_reg & BIT(24)) {
		/* Pass through mode */
		mult = div = 1;
	} else {
		/* F = 25Mhz * [(M + 2) / (n + 1)] / (p + 1) */
		union ast2600_pll_reg reg;
		reg.w = pll_reg;
		mult = (reg.b.m + 1) / (reg.b.n + 1);
		div = (reg.b.p + 1);
	}
	rate = ((clkin * mult)/div);

	for(i = 0; i < 8; i++) {
		div = (i + 1) * 2;
		if ((rate / div) <= 200000000)
			break;
	}

	clk_sel &= ~(0x7 << 12);
	clk_sel |= (i << 12) | BIT(11);
	writel(clk_sel, 0x1e6e2300);

	setbits_le32(0x1e6e2300, enableclk_bit);

	return;

}
