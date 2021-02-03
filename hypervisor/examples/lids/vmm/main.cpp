//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//cmake ../hypervisor/ -DDEFAULT_VMM=lids

#include <vmm.h>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <fstream>

using phys_addr_t = uintptr_t; ///< Phys Address Type (as Int)
using virt_addr_t = uintptr_t;
using namespace bfvmm::x64::cr3; ///< Virt Address Type (as Ptr)
using namespace bfvmm::x64;

using size_type = size_t;     ///< Size Type
using entry_type = uintptr_t; ///< Entry Type
using index_type = std::ptrdiff_t;

std::vector<entry_type> ESKernel;
bool allowWalk = true; //in near future will be an object with the entire state

void global_init()
{
    bfdebug_info(0, "running LIDS example");
    bfdebug_lnbr(0);
}
const char *hex_char_to_bin(char c)
{
    // TODO handle default / error
    switch (toupper(c))
    {
    case '0':
        return "0000";
    case '1':
        return "0001";
    case '2':
        return "0010";
    case '3':
        return "0011";
    case '4':
        return "0100";
    case '5':
        return "0101";
    case '6':
        return "0110";
    case '7':
        return "0111";
    case '8':
        return "1000";
    case '9':
        return "1001";
    case 'A':
        return "1010";
    case 'B':
        return "1011";
    case 'C':
        return "1100";
    case 'D':
        return "1101";
    case 'E':
        return "1110";
    case 'F':
        return "1111";
    }
}

std::string hex_str_to_bin_str(const std::string &hex)
{
    // TODO use a loop from <algorithm> or smth
    std::string bin;
    for (unsigned i = 0; i != hex.length(); ++i)
        bin += hex_char_to_bin(hex[i]);
    return bin;
}
//to convert from phys to virt currentVirtAdress = g_mm->physint_to_virtint(cr3PhysicalAddr);
void printPTE(entry_type entryOfMap_)
{
    bfdebug_info(0, "------------------PAGE TABLE ENTRY OF MAP (PTE)---------------------------");

    bool present = x64::pt::entry::present::is_enabled(entryOfMap_);
    bool us = x64::pt::entry::us::is_enabled(entryOfMap_);
    bool rw = x64::pt::entry::rw::is_enabled(entryOfMap_);
    bool pwt = x64::pt::entry::pwt::is_enabled(entryOfMap_);

    bool pcd = x64::pt::entry::pcd::is_enabled(entryOfMap_);
    bool accessed = x64::pt::entry::accessed::is_enabled(entryOfMap_);
    bool dirty = x64::pt::entry::dirty::is_enabled(entryOfMap_);
    bool g = x64::pt::entry::g::is_enabled(entryOfMap_);

    bfdebug_info(0, "                -permissions-");
    if (present)
    {
        bfdebug_info(0, "PRESENT IN PHYSICAL MEMORY");
    }
    else
    {
        bfdebug_info(0, "PAGE FAULT(NOT PRESENT)");
    }
    if (rw)
    {
        bfdebug_info(0, "READ/WRITE");
    }
    else
    {
        bfdebug_info(0, "READ ONLY");
    }
    if (us)
    {
        bfdebug_info(0, "USER PAGE");
    }
    else
    {
        bfdebug_info(0, "SUPERVISOR PAGE");
    }
    if (pwt)
    {
        bfdebug_info(0, "WRITE-THROUGH POLICY");
    }
    else
    {
        bfdebug_info(0, "WRITE-BACK POLICY");
    }
    if (pcd)
    {
        bfdebug_info(0, "CACHE DISABLED (WON'T BE CACHED)");
    }
    else
    {
        bfdebug_info(0, "CACHE ENABLED");
    }
    if (accessed)
    {
        bfdebug_info(0, "ACCESSED (read/write)");
    }
    else
    {
        bfdebug_info(0, "NOT ACCESSED");
    }
    if (dirty)
    {
        bfdebug_info(0, "DIRTY (has been written)");
    }
    else
    {
        bfdebug_info(0, "NOT DIRTY");
    }
    if (g)
    {
        bfdebug_info(0, "GLOBAL (CR4)");
    }
    else
    {
        bfdebug_info(0, "NOT GLOBAL");
    }
}

void listESKernelCode(uint64_t entry_)
{

    bool us = x64::pt::entry::us::is_enabled(entry_); //check for kernel supervisor
    bool rw = x64::pt::entry::rw::is_enabled(entry_); // is RO
    bool xd = x64::pt::entry::xd::is_enabled(entry_); //only exectuable
    if (!rw && !us && !xd)
    {
        ESKernel.push_back(entry_);
        //here goes a map(key, value) where key is entry and value=[rw,us,xd]
    }
    std::clog << std::hex << entry_ << " PTE ";
    if (rw)
    {
        std::clog << " R/W ";
    }
    else
    {
        std::clog << " RO ";
    }
    if (us)
    {
        std::clog << " US ";
    }
    else
    {
        std::clog << " S ";
    }
    if (xd)
    {
        std::clog << " X ";
    }
    else
    {
        std::clog << " NX ";
    }

    std::clog << "\n";
}
void walkPT()
{
    //bfignored(vcpu);
    bfdebug_info(0, "Init CR3 walkthrough: ");

    entry_type entryOfMap;
    virt_addr_t pgdPointer;

    //    constexpr const auto KERNEL_START = 0xFFFF800000000000;
    uint64_t KERNEL_START = 0xFFFF800000000000;
    uint64_t KERNEL_FINSH = 0xFFFFc87fffffffff;
    //auto KERNEL_START = 0x1000800000000000;
    mmap *cr3Mmap = vmm_cr3();
    uintptr_t cr3PhysicalAddr = cr3Mmap->cr3();
    uint64_t cr3_Phys = reinterpret_cast<uint64_t>(cr3PhysicalAddr);
    auto cr3MmapPhys = g_cr3;
    virt_addr_t cr3VirtAdress = g_mm->physint_to_virtint(cr3PhysicalAddr);
    long counter = 0;

    bool found = false;
    bfdebug_info(0, "------------------CR3 ---------------------------");
    bfdebug_nhex(0, "PHYSICAL ADDRESS:", cr3PhysicalAddr);
    bfdebug_nhex(0, "LINEAR ADDRESS:", cr3VirtAdress);
    //auto dest = (cr3VirtAdress>>12) & 0xFFFFFFFFF; //Cogera a partir de los 12 ultimos bits, i aplicara una mascara hasta los 51

    //CR3 stores phys direction where pgd is
    //but now always are equivalent:
    //At least since Linux 2.6, pgd and cr3 may or may not be equivalent depending on two factors:
    //Whether pgd is larger than the virtual base address of the kernel image __START_KERNEL_map.
    //phys_base, which is the difference between the compile-time physical base address of the kernel image and the run-time physical base address of the image. If the image has been relocated, phys_base would not be zero.
    //The translation process is performed by a function called __phys_addr which you can refer to to follow the following examples.
    //Source: https://stackoverflow.com/questions/54973030/difference-between-cr3-value-and-pgd-t

    //while(counter<1000){
    bfdebug_info(0, "--------------------START--------------------");
    bfdebug_nhex(0, "START_KERNEL Linear Address:", KERNEL_START);

    std::vector<uint64_t> pa_PML4s;
    std::vector<uint64_t> pa_pdptes;
    std::vector<uint64_t> pa_pds;
    std::vector<uint64_t> pa_ptes;

    //phys_addr_t pa_pml4e = (cr3PhysicalAddr & 0xFFFFFFFFFF000) + ((KERNEL_START >> 39) & 0x1FF); //Where 1FF is 9 bits (47:39)
    //acces content of phys to get virt
    // std::fstream pml4_file;
    //pml4_file.open("/home/daniel/Desktop/Bareflank_LIDS/pml4Dump.txt");
    /*if(!pml4_file){
            std::clog<<"FILE NOT CREATED";
        }*/
    std::clog << "-----------------------------PML4------------------------------ \n";

    uint64_t pa_pml4 = cr3PhysicalAddr;
    uint64_t *virtPml4 = reinterpret_cast<uint64_t *>(cr3Mmap->cr3Virt().data()); //casteo a puntero
    //int PML4i = x64::pml4::index(virtPml4); //same as mask ((KERNEL_START >> 39) & 0x1FF);
    int PML4i = x64::pml4::index(KERNEL_START);
    uint64_t pa_pml4e;

    for (int i = 0; i < x64::pml4::num_entries; i++)
    {
        uint64_t pml4E = virtPml4[i];
        if (PML4i == i)
        {
            pa_pml4e=pml4E;
            //pml4_file << "KERNEL Virt PML4e " <<std::dec << i;
            std::clog << "KERNEL INDEX ";

        }else{
                //pml4_file << "Virt PML4e "  <<std::dec << i;
                //std::clog << "Virt PML4e "  <<std::dec << i;
        }
        //pml4_file << std::hex <<  ": 0x" << pml4E << "\n";

        if (pml4E != 0)
        { //this condition is only for testing, it should be the same as the PML4i
            pa_PML4s.push_back(pml4E);
            std::clog << "Virt PML4e " << std::dec << i;
            std::clog << std::hex << ": 0x" << pml4E << "\n";
        }
    }

    //pml4_file << "Target PML4 Offset is: "<< std::dec << PML4i <<"\n";
    std::clog << "Target PML4 Offset is: "<< std::dec << PML4i <<"\n";

        std::clog<<"-----------------------------PDPT------------------------------ \n";
        //pml4_file.close();//make dump>
        
        for(uint64_t pa_pml4e : pa_PML4s ){

            uint64_t pa_pdpt = (pa_pml4e & 0xFFFFFFFFFF000 );
            uint64_t* virtPdpt  = reinterpret_cast<uint64_t*>(g_mm->physint_to_virtptr(pa_pdpt)); //casteo a puntero
            int PDPTi = x64::pdpt::index(KERNEL_START);

            for(int i=0;i<x64::pdpt::num_entries;i++){
                uint64_t PDPTe = virtPdpt[i];
                if(PDPTi==i){
                    std::clog << "KERNEL INDEX ";

                }/*else{
                    std::clog << "Virt PDPTe "  <<std::dec << i;
                }*/
                //std::clog << std::hex <<  ": 0x" << PDPTe << "\n";
                if(PDPTe!=0){
                    pa_pdptes.push_back(PDPTe);
                    std::clog << "Virt PDPTe "  <<std::dec << i;
                    std::clog << std::hex <<  ": 0x" << PDPTe << "\n";
                }
            }
            std::clog<< "Target PDPT Offset is: "<< std::dec << PDPTi <<"\n";
        }

        
        
        std::clog<<"-----------------------------PD------------------------------ \n";

        for(uint64_t pa_pdpte : pa_pdptes ){

            uint64_t pa_pd = (pa_pdpte & 0xFFFFFFFFFF000);
            uint64_t* virtPd  = reinterpret_cast<uint64_t*>(g_mm->physint_to_virtptr(pa_pd)); //casteo a puntero
            int PDi = x64::pd::index(cr3VirtAdress);

            for(int i=0;i<x64::pd::num_entries;i++){
                uint64_t PDe = virtPd[i];
                if(PDi==i){
                    std::clog << "KERNEL INDEX ";
                }
                /*}else{
                    std::clog << "Virt PDe "  <<std::dec << i;
                }*/
                if(PDe!=0){
                    pa_pds.push_back(PDe);
                    std::clog << "Virt PDe "  <<std::dec << i;
                    std::clog << std::hex <<  ": 0x" << PDe << "\n";
                }

               
            }

            std::clog<< "Target PD Offset is: "<< std::dec << PDi <<"\n";
        }

        for(uint64_t pa_pde : pa_pds ){
            auto pa_pt = (pa_pde & 0xFFFFFFFFFF000);
            uint64_t* virtPt  = reinterpret_cast<uint64_t*>(g_mm->physint_to_virtptr(pa_pt)); //casteo a puntero
            int PTi = x64::pt::index(cr3VirtAdress);

            for(int i=0;i<x64::pt::num_entries;i++){
                uint64_t PTe = virtPt[i];
                if(PTi==i){
                    std::clog << "KERNEL INDEX: ";
                }/*else{
                    std::clog << "Virt PTe "  <<std::dec << i;
                }*/
                if(PTe!=0){
                    pa_ptes.push_back(PTe);
                    std::clog << "Virt PDe "  <<std::dec << i;
                    std::clog << std::hex <<  ": 0x" << PTe << "\n";

                }
            }

            std::clog<< "Target PT Offset is: "<< std::dec << PTi <<"\n";
        }

        for (uint64_t pte : pa_ptes){
            //printPTE(pte);
            listESKernelCode(pte); //will save X,RO, supervisor
        }
        //listESKernelCode(PTe);


        


        //bfdebug_ndec(0,"Counter",counter);
        bfdebug_info(0,"--------------------FINISH--------------------");

        //printPTE(entryPte.first);
        //KERNEL_START+=4095; //FFF that is offset page
        //counter++;
    
    //}
    
    /*for(long i=0;i< ESKernel.size();i++)
    {
        bfdebug_nhex(0,"ES Page: ",ESKernel[i]);
    }
    bfdebug_ndec(0,"Executable Suppervisor PTE's: ", ESKernel.size());

     */
}
void vcpu_init_nonroot(vcpu_t *vcpu)
{
    //vcpu->dump("Thats the state dump");
    int i = 0;

    while (allowWalk)
    {
        if (i == 1)
        {
            allowWalk = false;
        }
        walkPT();
        i++;
    }
}
