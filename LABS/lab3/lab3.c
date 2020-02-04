#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define CR0_PE 0x1
#define CR0_PG (1<<31) //0x80000000
#define CR4_PSE (1<<4)
#define PF_EXCEPTION 14

#define PTE_TRIVIAL_SELFMAP     0x007  //               //present read-write user 4Kb
#define PTE_TRIVIAL_LARGE       0x087  //0000 1000 0111 //present read-write user 4Mb
#define PTE_TRIVIAL_NONPRESENT  0xBA4  //---- ---- ---0
#define PTE_TRIVIAL_FAULTONCE   0x086  //same as PTE_TRIVIAL_LARGE but non-present
#define PTE_NOT_PRESENT         0xFFFFFFFE

#pragma pack (push, 1)

typedef union _PTE {
    uint32 raw;
    struct {
        uint32 p:1;
        uint32 rw:1;
        uint32 us:1;
        uint32 xx:4; //PCD,PWT,A,D
        uint32 ps:1;
        uint32 g:1;
        uint32 avl:3;
        uint32 pfn:20;
    };
} PTE, *PPTE;

typedef struct _IDTENTRY {
    uint16 offset_l;
    uint16 seg_sel;
    uint8  zero;
    uint8  flags;
    uint16 offset_h;
} IDTENTRY, *PIDTENTRY;

typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _SELECTOR {
    uint16 raw;
    struct {
        uint16 pl:2;
        uint16 table:1;
        uint16 index:13;
    };
} SELECTOR, *PSELECTOR;

#define BASE_FROM_DESCRIPTOR(x) ((x->desc.base_low) | (x->desc.base_mid << 16) | (x->desc.base_high << 24))
#define LIMIT_FROM_DESCRIPTOR(x) (((x->desc.limit_low) | (x->desc.limit_high << 16)) << (x->desc.g ? 12 : 0))

typedef struct _SYSINFO {
    SELECTOR cs;
    uint32 cr0;
    DTR gdt;
    DTR idt;
    SELECTOR ldt;
    SELECTOR tr;
} SYSINFO, *PSYSINFO;

void get_sysinfo(PSYSINFO psysinfo)
{
    uint16 _cs =0;
    uint32 _cr0 =0;
    DTR* _gdt = &psysinfo->gdt;
    DTR* _idt = &psysinfo->idt;
    uint16 _ldt =0;
    uint16 _tr =0;

    __asm {
        mov eax, cr0
        mov _cr0, eax
        mov ax, cs
        mov _cs, ax

        mov eax, _gdt
        sgdt [eax]
        mov eax, _idt
        sidt [eax]
        sldt _ldt
        str _tr

        //xor ax, ax
        //mov cs, ax
    }

    psysinfo->cr0 = _cr0;
    psysinfo->cs.raw = _cs;
    psysinfo->ldt.raw = _ldt;
    psysinfo->tr.raw = _tr;
}

SYSINFO sysinfo;
char* PF_ADDR = 0;
uint32 my_ptr = 0;
uint32 incr = 0;

void idt_set_gate(PIDTENTRY idt, uint8 num, uint32 offset, uint16 seg_sel, uint8 flags) {
    idt[num].offset_l = offset & 0xFFFF;
    idt[num].offset_h = (offset >> 16) & 0xFFFF;
    idt[num].seg_sel = seg_sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

void __declspec( naked ) pf_handler(void)
{
    __asm {
        //cli
        push eax
        push edx
        mov edx, cr2
        cmp edx, PF_ADDR        //"my" address
        jnz pf
        mov eax, my_ptr         //pde/pte corresponding to "my" unpresent address
        or dword ptr[eax], 1h   //restore P bit
        invlpg [eax]            //invalidate all paging caches for "my" address
        lea eax, incr
        add [eax], 1            //inc counter of "my" #PF
        jmp done
pf:
        pop edx
        pop eax
        push old_segment
        push old_offset
        retf
done:
        pop edx
        pop eax
        //sti
        add esp, 4
        iretd
    }
}

void paging_task()
{
    int i = 0, j = 0;
    uint32 k4 = 4*1024;
    uint32 m4 = 4*1024*1024;
    char* addr = (char*)0xF007F000;
    void* p1 = malloc(k4*2);
    uint32 _p1 = (uint32)p1;
    uint32 _pd_aligned = (_p1 & ~(k4-1)) + k4;
    uint32 _pd = _pd_aligned + 0;
    PPTE pd = (PPTE)_pd;

    void* p2 = malloc(m4*2);
    uint32 _p2 = (uint32)p2;
    uint32 _pt_aligned = (_p2 & ~(m4-1)) + m4;
    uint32 _pt = _pt_aligned + 0;
    PPTE pt = (PPTE)_pt;

    printf("malloc 8Kb at 0x%08X-0x%08x, aligned at 0x%08X \n", _p1, _p1+k4*2, _pd_aligned);

    //trivial mapping
    for (i=0;i<1024;i++) {
        pd[i].raw = (uint32)(pt + i*1024);
        pd[i].raw |= PTE_TRIVIAL_SELFMAP;
    }
    for (i=0;i<1024;i++)
        for (j=0;j<1024;j++) {
            int idx = i*1024 + j;
            pt[idx].raw = idx * 0x1000;
            pt[idx].raw |= PTE_TRIVIAL_SELFMAP;
        }
    pt[0x3c0*0x400+0x7F].raw &= PTE_NOT_PRESENT; //virtual range 0xF007F000-0xF007FFFF is unpresent
    __asm {
        pushfd
        cli
        mov eax, _pd_aligned
        mov cr3, eax         //this also resets instruction cache
        mov eax, cr4
        or eax, 0x90
        mov cr4, eax        //enable CR4.PSE and CR4.PGE
        mov eax, cr0
        or eax, 0x80000000
        mov cr0, eax        //enable CR0.PG
        popfd
    }

    PF_ADDR = addr + 17;
    my_ptr = (uint32)(&(pt[0x3c0*0x400+0x7F]));
}

void pf_test(PSYSINFO sysinfo)
{
    PIDTENTRY idt_table = (PIDTENTRY)sysinfo->idt.base;
    uint32 old_offset = idt_table[PF_EXCEPTION].offset_h << 16 | idt_table[PF_EXCEPTION].offset_l;
    uint16 old_segment = idt_table[PF_EXCEPTION].seg_sel;
    uint32 new_offset = 0;
    uint16 new_segment = 0;

    printf("MY PF counter: %d\n", incr);
    __asm {
        mov edx, offset pf_handler
        mov new_offset, edx
        mov ax, seg pf_handler
        mov new_segment, ax
    }

    idt_set_gate(idt_table, PF_EXCEPTION, new_offset, new_segment, idt_table[PF_EXCEPTION].flags);

    printf("I am memory %d\n", *PF_ADDR); // to recover page
    printf("I am memory %d\n", *(PF_ADDR + 4)); // not to see any page fault

    printf("MY PF counter: %d\n", incr);
    ((PPTE)my_ptr)->raw &= PTE_NOT_PRESENT;
    printf("I am memory %d\n", *(PF_ADDR + 9)); // to see default page fault
}

void main()
{
    printf("Hello, world! \n");
    get_sysinfo(&sysinfo);
    paging_task();
    pf_test(&sysinfo);
}
