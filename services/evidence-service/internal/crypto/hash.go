package crypto

import (

"crypto/sha256"
"fmt"

)

func GenerateHash(data string) string {

hash := sha256.Sum256([]byte(data))

return fmt.Sprintf("%x", hash)

}