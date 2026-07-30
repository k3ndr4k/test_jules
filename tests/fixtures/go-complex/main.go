package main

import "fmt"

func ultraComplexFunction(a, b, c int) {
	if a > 0 {
		for i := 0; i < a; i++ {
			if b > i || c < i && (a+b) > 0 {
				switch b {
				case 1:
					if c == 1 || c == 2 {
						fmt.Println("1")
					} else if c == 3 && a > 5 {
						fmt.Println("1.3")
					}
				case 2:
					for j := 0; j < c; j++ {
						if j%2 == 0 || j%3 == 0 {
							fmt.Println("2.even")
						} else {
							fmt.Println("2.odd")
						}
					}
				case 3:
					if a == b || b == c || c == a {
						fmt.Println("3.match")
					}
				default:
					if a == b && b != 0 || c > 10 {
						fmt.Println("default.match")
						for k := 0; k < 5; k++ {
							if k == 2 {
								continue
							} else if k == 4 {
								break
							}
						}
					}
				}
			}
		}
	} else if a < 0 && b < 0 {
		fmt.Println("negative")
	} else {
		fmt.Println("zero")
	}
}

func main() {
	ultraComplexFunction(10, 2, 5)
}
