package lib

import (
	"fmt"
	"strings"
)

func ErrReader(err error) (function string, e error) {
	str := strings.Split(err.Error(), ":")
	function = str[0]
	e = fmt.Errorf(str[1])
	return
}
