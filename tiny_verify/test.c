#include "sphincs-verify.h"

int main(void) {

    sphincs_plus_verify( "abc", 3,
                "def", 3,
                "ghi" );
    return 0;
}
