#if !defined( SPHINCS_HYBRID_ )
#define SPHINCS_HYBRID_

#include <stdbool.h>
#include <stddef.h>

#define LEN_SPHINCSPLUS_SIG 17064

/*
 * Verify a signature
 */
bool sphincs_plus_verify( const void *message, size_t len_message,
                const void *signature, size_t len_signature,
                const void *public_key );

#endif /* SPHINCS_HYBRID_ */
