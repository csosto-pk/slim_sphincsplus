#if !defined(tune_h_)
#define TUNE_H_

/*
 * This defines whether we use OpenSSL to compute SHA-256 hashes, or we use
 * our own implementation.
 *
 * Reasons to use OpenSSL: it's a *lot* faster (>2x in my tests, and that's
 * without the new-fangled SHA-256 instructions; if you do have those, I'd
 * expected the speed-up to be even more extreme).
 *
 * Reasons to use our own implementation: * it's possible that there is some
 * platform that doesn't provide OpenSSL.
 */
#define USE_OPENSSL 1   /* 0 -> Use our own instrumented SHA-256 */
                        /*      implementation */
                        /* 1 -> Use the OpenSSL implementation */

#endif /* TUNE_H_ */
