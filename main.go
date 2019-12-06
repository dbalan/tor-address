package main

import (
	"fmt"
)

func main() {
	fmt.Println("hello world")
}

func ComputeAddr(priv string) (string, error) {
	return priv, nil
}
