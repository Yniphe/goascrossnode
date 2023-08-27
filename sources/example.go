package main

import "C"
import (
	tls "github.com/refraction-networking/utls"
	"io"
	"net/http"
)

//export MyFunction
func MyFunction() *C.char {
	transport, err := Transport("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49172-49161-49171-156-157-47-53,0-23-65281-10-11-35-13-51-45-43,29-23-24,0", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		println(err.Error())
		return nil
	}

	client := &http.Client{
		Transport: transport,
		//Timeout:   5000,
	}

	resp, err := client.Get("https://tools.scrapfly.io/api/fp/ja3?extended=1")

	if err != nil {
		println(err.Error())
		return nil
	}

	println(resp.Status)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}

	}(resp.Body)

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		println(err.Error())
		return nil
	}

	return C.CString(string(body))
}

func main() {

}
