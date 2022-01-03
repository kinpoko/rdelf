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
	Long:  `A CLI application for parsing ELF headers.`,

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

		hed, err := cmd.Flags().GetBool("hed")
		if err != nil {
			return err
		}
		if hed {

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
			fmt.Printf("Section header string table index: %d \n", h.StringTableIndex)
			fmt.Printf("\n")
		}

		progh, err := cmd.Flags().GetBool("progh")
		if err != nil {
			return err
		}
		if progh {
			phs, err := readelf.ReadProgramHeaders(b, h.StartOfPHeader, h.NumOfPHeader, h.SizeOfPHeader)
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
		}
		segh, err := cmd.Flags().GetBool("segh")
		if err != nil {
			return err
		}
		if segh {
			shs, err := readelf.ReadSectionHeaders(b, h.StartOfSHeader, h.NumOfSHeader, h.SizeOfSHeader)
			if err != nil {
				return err
			}
			for i, sh := range shs {
				fmt.Printf("Section Headers[%d]:\n", i)
				fmt.Println("Name: " + sh.NameString)
				fmt.Println("Type: " + sh.Type)
				fmt.Println("Flags: " + sh.Flags)
				fmt.Printf("Address: 0x%x\n", sh.Address)
				fmt.Printf("Offset: 0x%x\n", sh.Offset)
				fmt.Printf("Size: 0x%x\n", sh.Size)
				fmt.Printf("Link: %d\n", sh.Link)
				fmt.Printf("Info: %d\n", sh.Info)
				fmt.Printf("Alignment: 0x%x\n", sh.Alignment)
				fmt.Printf("Entry Size: 0x%x\n", sh.EntrySize)
				fmt.Print("\n")
			}
		}
		return nil

	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().Bool("hed", false, "display elf header")
	rootCmd.Flags().BoolP("progh", "l", false, "display program headers")
	rootCmd.Flags().BoolP("segh", "S", false, "display section headers")
}
