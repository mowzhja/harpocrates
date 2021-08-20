// A file to experiment with the use of channels, select and possibly context (useful for when i'll have to use all three in the actual main)
package main

// func main() {
// 	readc := make(chan string)
// 	writec := make(chan string)
// 	defer close(writec)

// 	for {
// 		go writeremote(readc, "remote")
// 		go writelocal(readc, "local")

// 		select {
// 		case msgr := <-readc:
// 			// read from remote
// 			fmt.Println("Read:", msgr)
// 		case msgw := <-writec:
// 			// write to remote
// 			fmt.Println("Writing:", msgw)
// 		}
// 		time.Sleep(1 * time.Second)
// 	}
// }

// // simulates writes from remote (on the read channel)
// func writeremote(rc chan string, data string) {
// 	time.Sleep(2 * time.Second) // write locally mostly, and read very little
// 	fmt.Println("wrote from remote:", data)
// 	rc <- data

// }

// // writes locally (on the write channel)
// func writelocal(wc chan string, data string) {
// 	fmt.Println("wrote locally:", data)
// 	wc <- data
// }
