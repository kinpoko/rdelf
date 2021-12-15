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

		h, err := readelf.ReadELFHeader(b)
		if err != nil {
			return err
		}

		fmt.Print("Magic: ")
		for _, n := range h.Magic {
			fmt.Printf("%x ", n)
		}
		fmt.Printf("\n")

		fmt.Println("Class: " + h.Class)
		fmt.Println("Data: " + h.Data)
		fmt.Printf("Version: %x\n", h.Version)
		fmt.Println("Type: " + h.Type)
		fmt.Println("Machine: " + h.Machine)
		fmt.Printf("EntryPoint: 0x%x\n", h.EntryPoint)
		fmt.Printf("Start of Program headers: %d (bytes)\n", h.StartOfPHeader)
		fmt.Printf("Start of Section headers: %d (bytes)\n", h.StartOfSHeader)
		fmt.Printf("Number of Program headers: %d \n", h.NumOfPHeader)
		fmt.Printf("Number of Section headers: %d \n", h.NumOfSHeader)
		fmt.Printf("\n")

		phs, err := readelf.ReadProgramHeader(b, h.StartOfPHeader, h.NumOfPHeader, h.SizeOfPHeader)
		if err != nil {
			return err
		}
		for i, ph := range phs {
			fmt.Printf("Program Headers[%d]:\n", i)
			fmt.Println("Type: " + ph.Type)
			fmt.Println("Flags: " + ph.Flags)
			fmt.Printf("Offset: 0x%x\n", ph.Offset)
			fmt.Printf("VirtAddr: 0x%x\n", ph.VAddr)
			fmt.Printf("PhysAddr: 0x%x\n", ph.PAddr)
			fmt.Printf("FileSize: 0x%x\n", ph.FSize)
			fmt.Printf("MemSize: 0x%x\n", ph.MSize)
			fmt.Print("\n")
		}

		return nil

	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
}
