/*
 * (C) Copyright ASPEED Technology Inc.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */


//#define DEBUG 1

#include <common.h>
#include <log.h>
#include <asm/io.h>
#include <malloc.h>

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/iopoll.h>

#include "aspeed_hace.h"

static int ast_hace_wait_isr(u32 reg, u32 flag, int timeout_us)
{
	u32 val;

	return readl_poll_timeout(reg, val, (val & flag) == flag, timeout_us);
}
static bool crypto_enabled = false;

#define SCU_BASE	0x1e6e2000

int digest_object(const void *src, unsigned int length, void *digest,
		  u32 method)
{
	debug("\n%s: ASPEED_HACE_STS='0x%08x'\n", __func__, readl(ASPEED_HACE_STS));
	debug("\n%s: SCU080h='0x%08x'\n", __func__, readl(SCU_BASE + 0x80));

	/* clear any pending interrupts */
	debug("\n%s: writing '0x%08x' to ASPEED_HACE_STS\n", __func__, HACE_HASH_ISR);
	writel(HACE_HASH_ISR, ASPEED_HACE_STS);

	debug("\n%s: ASPEED_HACE_STS='0x%08x'\n", __func__, readl(ASPEED_HACE_STS));
	debug("\n%s: SCU080h='0x%08x'\n", __func__, readl(SCU_BASE + 0x80));

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_SRC\n", __func__, (u32)src);
	writel((u32)src, ASPEED_HACE_HASH_SRC);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_DIGEST_BUFF\n", __func__, (u32)digest);
	writel((u32)digest, ASPEED_HACE_HASH_DIGEST_BUFF);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_DATA_LEN\n", __func__, length);
	writel(length, ASPEED_HACE_HASH_DATA_LEN);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_CMD\n", __func__, HACE_SHA_BE_EN | method);
	writel(HACE_SHA_BE_EN | method, ASPEED_HACE_HASH_CMD);

	return ast_hace_wait_isr(ASPEED_HACE_STS, HACE_HASH_ISR, 100000);
}

static void enable_crypto(void)
{
	if (crypto_enabled)
		return;
	else
		crypto_enabled = true;

	writel(BIT(4), SCU_BASE + 0x040);
	udelay(300);
	writel(BIT(24), SCU_BASE + 0x084);
	writel(BIT(13), SCU_BASE + 0x084);
	mdelay(30);
	writel(BIT(4), SCU_BASE + 0x044);

}

void hw_sha1(const unsigned char *pbuf, unsigned int buf_len,
	       unsigned char *pout, unsigned int chunk_size)
{
	int rc;

	enable_crypto();

	rc = digest_object(pbuf, buf_len, pout, HACE_ALGO_SHA1);
	if (rc)
		debug("HACE failure\n");
}

void hw_sha256(const unsigned char *pbuf, unsigned int buf_len,
	       unsigned char *pout, unsigned int chunk_size)
{
	int rc;

	enable_crypto();

	rc = digest_object(pbuf, buf_len, pout, HACE_ALGO_SHA256);
	if (rc)
		debug("HACE failure\n");
}

void hw_sha512(const unsigned char *pbuf, unsigned int buf_len,
	       unsigned char *pout, unsigned int chunk_size)
{
	int rc;

	enable_crypto();

	rc = digest_object(pbuf, buf_len, pout, HACE_ALGO_SHA512);
	if (rc)
		debug("HACE failure\n");
}

#if IS_ENABLED(CONFIG_SHA_PROG_HW_ACCEL)
int aspeed_sg_digest(struct aspeed_sg_list *src_list,
					 unsigned int list_length, unsigned int length,
					 void *digest, unsigned int method)
{
	
	debug("\n%s: ASPEED_HACE_STS='0x%08x'\n", __func__, readl(ASPEED_HACE_STS));
	debug("\n%s: SCU080h='0x%08x'\n", __func__, readl(SCU_BASE + 0x80));

	/* clear any pending interrupts */
	debug("\n%s: writing '0x%08x' to ASPEED_HACE_STS\n", __func__, HACE_HASH_ISR);
	writel(HACE_HASH_ISR, ASPEED_HACE_STS);

	debug("\n%s: ASPEED_HACE_STS='0x%08x'\n", __func__, readl(ASPEED_HACE_STS));
	debug("\n%s: SCU080h='0x%08x'\n", __func__, readl(SCU_BASE + 0x80));

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_SRC\n", __func__, (u32)src_list);
	writel((u32)src_list, ASPEED_HACE_HASH_SRC);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_DIGEST_BUFF\n", __func__, (u32)digest);
	writel((u32)digest, ASPEED_HACE_HASH_DIGEST_BUFF);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_DATA_LEN\n", __func__, length);
	writel(length, ASPEED_HACE_HASH_DATA_LEN);

	debug("\n%s: writing '0x%08x' to ASPEED_HACE_HASH_CMD\n", __func__, HACE_SHA_BE_EN | HACE_SG_EN | method);
	writel(HACE_SHA_BE_EN | HACE_SG_EN | method, ASPEED_HACE_HASH_CMD);

	return ast_hace_wait_isr(ASPEED_HACE_STS, HACE_HASH_ISR, 100000);
}

int hw_sha_init(struct hash_algo *algo, void **ctxp)
{
	u32 method, digest_size;
	struct aspeed_hash_ctx *hash_ctx;
		
	if (!strcmp(algo->name, "sha1")) {
		method = HACE_ALGO_SHA1;
		digest_size = 20;
	}
	else if (!strcmp(algo->name, "sha256")) {
		method = HACE_ALGO_SHA256;
		digest_size = 32;
	}
	else if (!strcmp(algo->name, "sha512")) {
		method = HACE_ALGO_SHA512;
		digest_size = 64;
	}
	else  {
		return -ENOTSUPP;
	}

	hash_ctx = memalign(8, sizeof(struct aspeed_hash_ctx));

	if (hash_ctx == NULL) {
		debug("Cannot allocate memory for context\n");
		return -ENOMEM;
	}
	hash_ctx->method = method;
	hash_ctx->sg_num = 0;
	hash_ctx->len = 0;
	hash_ctx->digest_size = digest_size;
	*ctxp = hash_ctx;

	return 0;
}

int hw_sha_update(struct hash_algo *algo, void *ctx, const void *buf,
			    unsigned int size, int is_last)
{
	phys_addr_t addr = virt_to_phys((void *)buf);
	struct aspeed_hash_ctx *hash_ctx = ctx;

	if (hash_ctx->sg_num >= MAX_SG_32) {
		debug("HACE error: Reached maximum number of hash segments (%u)\n",
			  MAX_SG_32);
		free(ctx);
		return -EINVAL;
	}
	hash_ctx->sg_tbl[hash_ctx->sg_num].phy_addr = addr;
	hash_ctx->sg_tbl[hash_ctx->sg_num].len = size;
	if (is_last)
		hash_ctx->sg_tbl[hash_ctx->sg_num].len |= BIT(31);
	hash_ctx->sg_num++;
	hash_ctx->len += size;

	return 0;
}

int hw_sha_finish(struct hash_algo *algo, void *ctx, void *dest_buf,
		     int size)
{
	struct aspeed_hash_ctx *hash_ctx = ctx;
	void *digest;
	int rc;

	if (size < hash_ctx->digest_size) {
		debug("HACE error: insufficient size on destination buffer\n");
		rc = -EINVAL;
		goto cleanup;
	}
	digest = memalign(8, hash_ctx->digest_size);
	
	if (digest == NULL) {
		debug("HACE error: Cannot allocate memory for digest buffer\n");
		rc = -ENOMEM;
		goto cleanup;
	}

	enable_crypto();

	rc = aspeed_sg_digest(hash_ctx->sg_tbl, hash_ctx->sg_num,
						  hash_ctx->len, digest, hash_ctx->method);
	if (rc)
		debug("HACE Scatter-Gather failure\n");
	else
		memcpy(dest_buf, digest, hash_ctx->digest_size);

cleanup:
	if (digest)
		free(digest);
	free(ctx);

	return rc;
}
#endif
