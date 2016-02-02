// +build go1.4

package main

import "os"

func unsetenv(key string) {
	os.Unsetenv(key)
}
