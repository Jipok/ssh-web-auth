package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"unicode"

	"golang.org/x/crypto/ssh"
)

var (
	sshConfig *ssh.ServerConfig
	sshKey = flag.String("sshKey", "id_rsa", "private ssh key")

	// I need this because I don't know how else to pass the username 
	// from the callback to the rest of the program.
	global_locking_crutch string
)

func Equal(array1, array2 []byte) bool {
    if len(array1) != len(array2) {
        return false
    }
    for i := range array1 {
        if array1[i] != array2[i] {
            return false
        }
    }
    return true
}


func startSshServer() {
	sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: publicKeyCallback,
	}

	// You can generate a keypair with 'ssh-keygen -t rsa -C "test@example.com"'
	privateBytes, err := ioutil.ReadFile(*sshKey)
	if err != nil {
		log.Fatalf("Failed to load private key: %s", *sshKey)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	sshConfig.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("failed to listen on *:2222")
	}
	defer listener.Close()
	log.Printf("SSH server listening on %s", ":2222")

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		_, channels, _, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Printf("Failed to handshake: %s", err)
			continue
		}

		handleChannels(channels)
	}
}

func publicKeyCallback(sshConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("Trying to auth: %s (%s) - %s ", sshConn.User(), sshConn.ClientVersion(), sshConn.RemoteAddr())
	
	for name, localKey := range authorized_keys {
		// Make sure the key types match
		if remoteKey.Type() != localKey.keyType {continue}
		// Make sure every byte of the key matches up
		if ! Equal(remoteKey.Marshal(), localKey.keyData) {continue}
		// I need this because I don't know how else to pass the username 
		// from the callback to the rest of the program.
		global_locking_crutch = name
		log.Printf("Public key math: %s", name)
		return nil, nil
	}
	return nil, errors.New("Not authorized key")
}


func handleChannels(channels <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range channels {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// This code is still running in the same goroutine where
		// the ssh connection was opened. However, I have to start
		// the goroutine and use the username in. Due to the fact that
		// it is global, a race condition can occur.
		// Copy to avoid this
		username := global_locking_crutch
		
		// print our version of username
		channel.Write([]byte(fmt.Sprintf("Username: %s \n", username)))

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				str := string(req.Payload)
				var token = ""
				for _, rune := range str {
					if unicode.IsLetter(rune) || unicode.IsDigit(rune) || rune == '-' {
						token += string(rune)
					}
				}
				channel.Write([]byte(fmt.Sprintf("Request to add: %s \n", token)))

				if AddToken(username, token) {
					channel.Write([]byte(green("Access granted!\n")))
				} else {
					channel.Write([]byte(red("Access denied!\n")))
				}
				channel.Close()
			}
		}(requests)
	}
}
