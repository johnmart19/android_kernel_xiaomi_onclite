/*
 * CBC: Cipher Block Chaining mode
 *
 * Copyright (c) 2006-2016 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/cbc.h>
#include <crypto/internal/skcipher.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

struct crypto_cbc_ctx {
	struct crypto_cipher *child;
};

static int crypto_cbc_setkey(struct crypto_tfm *parent, const u8 *key,
			     unsigned int keylen)
{
	struct crypto_cbc_ctx *ctx = crypto_tfm_ctx(parent);
	struct crypto_cipher *child = ctx->child;
	int err;

	crypto_cipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(child, crypto_tfm_get_flags(parent) &
				       CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(child, key, keylen);
	crypto_tfm_set_flags(parent, crypto_cipher_get_flags(child) &
				     CRYPTO_TFM_RES_MASK);
	return err;
}

static inline void crypto_cbc_encrypt_one(struct crypto_skcipher *tfm,
					  const u8 *src, u8 *dst)
{
	struct crypto_cbc_ctx *ctx = crypto_skcipher_ctx(tfm);

	crypto_cipher_encrypt_one(ctx->child, dst, src);
}

static int crypto_cbc_encrypt(struct skcipher_request *req)
{
	return crypto_cbc_encrypt_walk(req, crypto_cbc_encrypt_one);
}

static inline void crypto_cbc_decrypt_one(struct crypto_skcipher *tfm,
					  const u8 *src, u8 *dst)
{
	struct crypto_cbc_ctx *ctx = crypto_skcipher_ctx(tfm);

	crypto_cipher_decrypt_one(ctx->child, dst, src);
}

static int crypto_cbc_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct skcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);

	while ((nbytes = walk.nbytes)) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			nbytes = crypto_cbc_decrypt_inplace(desc, &walk, child);
		else
			nbytes = crypto_cbc_decrypt_segment(desc, &walk, child);
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}

	return err;
}

static int crypto_cbc_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_instance *inst = (void *)tfm->__crt_alg;
	struct crypto_spawn *spawn = crypto_instance_ctx(inst);
	struct crypto_cbc_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_cipher *cipher;

	cipher = crypto_spawn_cipher(spawn);
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;
	return 0;
}

static void crypto_cbc_exit_tfm(struct crypto_tfm *tfm)
{
	struct crypto_cbc_ctx *ctx = crypto_tfm_ctx(tfm);
	crypto_free_cipher(ctx->child);
}

static struct crypto_instance *crypto_cbc_alloc(struct rtattr **tb)
{
	struct crypto_instance *inst;
	struct crypto_alg *alg;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_BLKCIPHER);
	if (err)
		return ERR_PTR(err);

	alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER,
				  CRYPTO_ALG_TYPE_MASK);
	if (IS_ERR(alg))
		return ERR_CAST(alg);

	inst = ERR_PTR(-EINVAL);
	if (!is_power_of_2(alg->cra_blocksize))
		goto out_put_alg;

	inst = crypto_alloc_instance("cbc", alg);
	if (IS_ERR(inst))
		goto out_put_alg;

	inst->alg.ivsize = alg->cra_blocksize;
	inst->alg.min_keysize = alg->cra_cipher.cia_min_keysize;
	inst->alg.max_keysize = alg->cra_cipher.cia_max_keysize;

	inst->alg.base.cra_ctxsize = sizeof(struct crypto_cbc_ctx);

	inst->alg.cra_blkcipher.ivsize = alg->cra_blocksize;
	inst->alg.cra_blkcipher.min_keysize = alg->cra_cipher.cia_min_keysize;
	inst->alg.cra_blkcipher.max_keysize = alg->cra_cipher.cia_max_keysize;

	inst->alg.cra_ctxsize = sizeof(struct crypto_cbc_ctx);

	inst->alg.cra_init = crypto_cbc_init_tfm;
	inst->alg.cra_exit = crypto_cbc_exit_tfm;

	inst->alg.cra_blkcipher.setkey = crypto_cbc_setkey;
	inst->alg.cra_blkcipher.encrypt = crypto_cbc_encrypt;
	inst->alg.cra_blkcipher.decrypt = crypto_cbc_decrypt;

out_put_alg:
	crypto_mod_put(alg);
	return inst;
}

static void crypto_cbc_free(struct crypto_instance *inst)
{
	crypto_drop_spawn(crypto_instance_ctx(inst));
	kfree(inst);
}

static struct crypto_template crypto_cbc_tmpl = {
	.name = "cbc",
	.alloc = crypto_cbc_alloc,
	.free = crypto_cbc_free,
	.module = THIS_MODULE,
};

static int __init crypto_cbc_module_init(void)
{
	return crypto_register_template(&crypto_cbc_tmpl);
}

static void __exit crypto_cbc_module_exit(void)
{
	crypto_unregister_template(&crypto_cbc_tmpl);
}

module_init(crypto_cbc_module_init);
module_exit(crypto_cbc_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CBC block cipher algorithm");
MODULE_ALIAS_CRYPTO("cbc");
