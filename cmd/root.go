package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kinpoko/rdelf/readelf"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rdelf [file name]",
	Short: "elf parser",
	Long:  ``,

	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()

		b, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		r, err := readelf.ReadHeader(b)
		if err != nil {
			return err
		}

		fmt.Print("Magic: ")
		for _, n := range r.Magic {
			fmt.Printf("%x ", n)
		}
		fmt.Printf("\n")

		fmt.Println("Class: " + r.Class)
		fmt.Println("Data: " + r.Data)
		fmt.Printf("Version: %x\n", r.Version)
		fmt.Println("Type: " + r.Type)

		return nil

	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
}
