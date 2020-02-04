#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define CR0_PE 0x1
#define CR0_PG (1<<31) //0x80000000

#define BASE_FROM_DESCRIPTOR(x) ((x->desc.base_low) | (x->desc.base_mid << 16) | (x->desc.base_high << 24))
#define LIMIT_FROM_DESCRIPTOR(x) ( (((x->desc.limit_low) | (x->desc.limit_high << 16)) << (x->desc.g ? 12 : 0)) - (x->desc.g ? 0x1 : 0x0) )
#define OFFSET_FROM_DESCRIPTOR(x) ((x->ig_desc.offset_lo) | (x->ig_desc.offset_hi << 16))

#define IS_TASK_GATE(x) (x->tg_desc.tg_type == 5)
#define IS_INTERRUPT_GATE(x) ((x->ig_desc.ig_type == 6) || (x->ig_desc.ig_type == 14))
#define IS_TRAP_GATE(x) ((x->trg_desc.trg_type == 7) || (x->trg_desc.trg_type == 15))
#define GATE_SIZE_FROM_DESCRIPTOR(x) ( ((x->trg_desc.trg_type >> 3) == 0) ? 4 : 2)

#define TSS_IDX 18
#define TSS_LIMIT 0x67
#define TSS_TEST_CR3 0x1367

#pragma pack (push, 1)
typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _DESCRIPTOR {
    struct {
        uint32 low;
        uint32 high;
    } raw;
    struct {
        //3A.figure 3-8
        uint16 limit_low;
        uint16 base_low;
        uint8 base_mid;
        uint8 type:4;
        uint8 s:1;
        uint8 dpl:2;
        uint8 p:1;
        uint8 limit_high:4;
        uint8 avl:1;
        uint8 rsrvd:1; //L bit only in 64bit
        uint8 db:1;
        uint8 g:1;
        uint8 base_high;
    } desc;
    struct {
        uint16 reserved1;
        uint16 tss_ss;
        uint8 reserved2;
        uint8 tg_type:5;
        uint8 dpl:2;
        uint8 p:1;
        uint8 reserved3;
    } tg_desc;
    struct {
        uint16 offset_lo;
        uint16 ss;
        uint8 reserved1:5;
        uint8 zeros:3;
        uint8 ig_type:5;
        uint8 dpl:2;
        uint8 p:1;
        uint16 offset_hi;
    } ig_desc;
    struct {
        uint16 offset_lo;
        uint16 ss;
        uint8 reserved1:5;
        uint8 zeros:3;
        uint8 trg_type:5;
        uint8 dpl:2;
        uint8 p:1;
        uint16 offset_hi;
    } trg_desc;
} DESCRIPTOR, *PDESCRIPTOR;

typedef union _SELECTOR {
    uint16 raw;
    struct {
        uint16 pl:2;
        uint16 table:1;
        uint16 index:13;
    };
} SELECTOR, *PSELECTOR;

typedef struct _SYSINFO {
    SELECTOR cs;
    uint32 cr0;
    DTR gdt;
    DTR idt;
    SELECTOR ldt;
    SELECTOR tr;
} SYSINFO, *PSYSINFO;

typedef struct _TSS {
    uint16 ptl;
    uint16 reserved1;
    uint32 esp0;
    uint16 ss0;
    uint16 reserved2;
    uint32 esp1;
    uint16 ss1;
    uint16 reserved3;
    uint32 esp2;
    uint16 ss2;
    uint16 reserved4;
    uint32 cr3;
    uint32 eip;
    uint32 eflags;
    uint32 eax;
    uint32 ecx;
    uint32 edx;
    uint32 ebx;
    uint32 esp;
    uint32 ebp;
    uint32 esi;
    uint32 edi;
    uint16 es;
    uint16 reserved5;
    uint16 cs;
    uint16 reserved6;
    uint16 ss;
    uint16 reserved7;
    uint16 ds;
    uint16 reserved8;
    uint16 fs;
    uint16 reserved9;
    uint16 gs;
    uint16 reserved10;
    uint16 ldt_ss;
    uint16 reserved11;
    uint8 T:1;
    uint8 reserved12:7;
    uint16 iomba;
} TSS, *PTSS;

void get_sysinfo(SYSINFO* psysinfo)
{
    uint16 _cs = 0;
    uint32 _cr0 = 0;
    DTR* _gdt = &psysinfo->gdt;
    DTR* _idt = &psysinfo->idt;
    uint16 _ldt = 0;
    uint16 _tr = 0;

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
    }

    psysinfo->cr0 = _cr0;
    psysinfo->cs.raw = _cs;
    psysinfo->ldt.raw = _ldt;
    psysinfo->tr.raw = _tr;
}

SYSINFO sysinfo;

void print_type(FILE* out_file, PDESCRIPTOR pdescriptor)
{
    if (pdescriptor->desc.s == 0)
    {
        fprintf(out_file, "\tTYPE: system, ");
        switch (pdescriptor->desc.type)
        {
            case 0:  fprintf(out_file, "reserved"); break;
            case 1:  fprintf(out_file, "16-bit TSS(Available)"); break;
            case 2:  fprintf(out_file, "LDT"); break;
            case 3:  fprintf(out_file, "16-bit TSS(Busy)"); break;
            case 4:  fprintf(out_file, "16-bit TSS Call Gate"); break;
            case 5:  fprintf(out_file, "Task Gate"); break;
            case 6:  fprintf(out_file, "16-bit Interrupt Gate"); break;
            case 7:  fprintf(out_file, "16-bit Trap Gate"); break;
            case 8:  fprintf(out_file, "reserved"); break;
            case 9:  fprintf(out_file, "32-bit TSS(Available)"); break;
            case 10: fprintf(out_file, "reserved"); break;
            case 11: fprintf(out_file, "32-bit TSS(Busy)"); break;
            case 12: fprintf(out_file, "32-bit TSS Call Gate"); break;
            case 13: fprintf(out_file, "reserved"); break;
            case 14: fprintf(out_file, "32-bit Interrupt Gate"); break;
            case 15: fprintf(out_file, "32-bit Trap Gate"); break;
            default: fprintf(out_file, "unknown"); break;
        }
    }
    else
    {
        fprintf(out_file, "\tTYPE: code/data, ");
        switch (pdescriptor->desc.type)
        {
            case 0:  fprintf(out_file, "read-only"); break;
            case 1:  fprintf(out_file, "read-only, accessed"); break;
            case 2:  fprintf(out_file, "read/write"); break;
            case 3:  fprintf(out_file, "read/write, accessed"); break;
            case 4:  fprintf(out_file, "read-only, expand-down"); break;
            case 5:  fprintf(out_file, "read-only, expand-down, accessed"); break;
            case 6:  fprintf(out_file, "read/write, expand-down"); break;
            case 7:  fprintf(out_file, "read/write, expand-down, accessed"); break;
            case 8:  fprintf(out_file, "execute-only"); break;
            case 9:  fprintf(out_file, "execute-only, accessed"); break;
            case 10: fprintf(out_file, "execute/read"); break;
            case 11: fprintf(out_file, "execute/read, accessed"); break;
            case 12: fprintf(out_file, "execute-only, conforming"); break;
            case 13: fprintf(out_file, "execute-only, conforming, accessed"); break;
            case 14: fprintf(out_file, "execute/read, conforming"); break;
            case 15: fprintf(out_file, "execute/read, conforming, accessed"); break;
            default: fprintf(out_file, "unknown"); break;
        }
    }
}

void print_gdt_descriptor(FILE* out_file, PDESCRIPTOR pdescriptor)
{
    if (pdescriptor->desc.p == 1)
    {
        fprintf(out_file, "\tSEL ADDR:0x%p BASE:0x%p LIMIT:0x%p\n" ,pdescriptor, BASE_FROM_DESCRIPTOR(pdescriptor), LIMIT_FROM_DESCRIPTOR(pdescriptor));
        print_type(out_file, pdescriptor);
        fprintf(out_file, " DPL:%d PRES:%d L:%d DB:%d G:%d\n\n", pdescriptor->desc.dpl,
            pdescriptor->desc.p, pdescriptor->desc.rsrvd, pdescriptor->desc.db, pdescriptor->desc.g);
    }
    else
    {
        fprintf(out_file, "\tSEL ADDR:0x%p, UNPRESENT\n", pdescriptor);
        print_type(out_file, pdescriptor);
        fprintf(out_file, " DPL: %d PRES: %d\n\n", pdescriptor->desc.dpl, pdescriptor->desc.p);
    }
}

void gdt_dump(FILE* out_file, PSYSINFO psysinfo)
{
    int i = 0;
    fprintf(out_file, "GDT Data:\n");
    for (i = 0; i*8 < psysinfo->gdt.limit; i++)
    {
        PDESCRIPTOR pdescriptor = (PDESCRIPTOR)(psysinfo->gdt.base+i*8);
        print_gdt_descriptor(out_file, pdescriptor);
    }
}

void idt_dump(FILE* out_file, PSYSINFO psysinfo)
{
    int i = 0;
    fprintf(out_file, "IDT Data:\n");
    for (i = 0; i*8 < psysinfo->idt.limit; i++)
    {
        PDESCRIPTOR pdescriptor = (PDESCRIPTOR)(psysinfo->idt.base+i*8);
        if (IS_TASK_GATE(pdescriptor))
        {
            fprintf(out_file, "\t0x%p, TASK GATE, TSS_SS: 0x%x, P: %d, DPL: %d\n", pdescriptor, pdescriptor->tg_desc.tss_ss,
                pdescriptor->tg_desc.p, pdescriptor->tg_desc.dpl);
        }
        else if (IS_INTERRUPT_GATE(pdescriptor))
        {
            fprintf(out_file, "\t0x%p, INPT GATE,     SS: 0x%x, P: %d, DPL: %d, OFF: 0x%p, GATE SIZE: %d\n", pdescriptor,
                pdescriptor->ig_desc.ss, pdescriptor->ig_desc.p, pdescriptor->ig_desc.dpl,
                OFFSET_FROM_DESCRIPTOR(pdescriptor), GATE_SIZE_FROM_DESCRIPTOR(pdescriptor));
        }
        else if (IS_TRAP_GATE(pdescriptor))
        {
            fprintf(out_file, "\t0x%p, TRAP GATE,     SS: 0x%x, P: %d, DPL: %d, OFF: 0x%p, GATE SIZE: %d\n", pdescriptor,
                pdescriptor->trg_desc.ss, pdescriptor->trg_desc.p, pdescriptor->trg_desc.dpl,
                OFFSET_FROM_DESCRIPTOR(pdescriptor), GATE_SIZE_FROM_DESCRIPTOR(pdescriptor));
        }
        else
        {
            fprintf(out_file, "\t0x%p, UNKN GATE, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        }
    }
}

void ldt_dump(FILE* out_file, PSYSINFO psysinfo)
{
    int i = 0;
    PDESCRIPTOR pldtdesc = (PDESCRIPTOR)(psysinfo->gdt.base+psysinfo->ldt.index*8);

    fprintf(out_file, "LDT data:\n");
    fprintf(out_file, "\tLDT selector: Index: 0x%x, TI: %x, RPL: %x\n", psysinfo->ldt.index,
        psysinfo->ldt.table, psysinfo->ldt.pl);
    print_gdt_descriptor(out_file, pldtdesc);
    fprintf(out_file, "LDT actual content:\n");
    for (i = 0; i*8 < LIMIT_FROM_DESCRIPTOR(pldtdesc); i++)
    {
        PDESCRIPTOR pdescriptor = (PDESCRIPTOR)(BASE_FROM_DESCRIPTOR(pldtdesc)+i*8);
        print_gdt_descriptor(out_file, pdescriptor);
    }
}

void tss_dump(FILE* out_file, PSYSINFO psysinfo)
{
    PDESCRIPTOR ptssdesc = NULL;
    PDESCRIPTOR pldtdesc = (PDESCRIPTOR)(psysinfo->gdt.base+psysinfo->ldt.index*8);

    fprintf(out_file, "TSS data:\n");
    fprintf(out_file, "\tTSS selector: Index: 0x%x, TI: %x, RPL: %x\n", psysinfo->tr.index,
        psysinfo->tr.table, psysinfo->tr.pl);
    if (psysinfo->tr.table == 1)
        ptssdesc = (PDESCRIPTOR)(BASE_FROM_DESCRIPTOR(pldtdesc)+psysinfo->tr.index*8);
    else
        ptssdesc = (PDESCRIPTOR)(sysinfo.gdt.base+sysinfo.tr.index*8);
    print_gdt_descriptor(out_file, ptssdesc);
    if (LIMIT_FROM_DESCRIPTOR(ptssdesc) == 0)
    {
        fprintf(out_file, "\tNO TSS\n");
    }
    else
    {
        PTSS ptss = ((PTSS)BASE_FROM_DESCRIPTOR(ptssdesc));

        fprintf(out_file, "============TSS==============\n");
        fprintf(out_file, "\tPrevious task link: 0x%x\n", ptss->ptl);
        fprintf(out_file, "\tESP0: 0x%x, SS0: 0x%x\n", ptss->esp0, ptss->ss0);
        fprintf(out_file, "\tESP1: 0x%x, SS1: 0x%x\n", ptss->esp1, ptss->ss1);
        fprintf(out_file, "\tESP2: 0x%x, SS2: 0x%x\n", ptss->esp2, ptss->ss2);
        fprintf(out_file, "\tCR3:  0x%x, EIP: 0x%x\n", ptss->cr3, ptss->eip);
        fprintf(out_file, "\tEFLAGS: 0x%x\n", ptss->eflags);
        fprintf(out_file, "\tEAX:  0x%x, ECX: 0x%x\n", ptss->eax, ptss->ecx);
        fprintf(out_file, "\tEDX:  0x%x, EBX: 0x%x\n", ptss->edx, ptss->ebx);
        fprintf(out_file, "\tESP:  0x%x, EBP: 0x%x\n", ptss->esp, ptss->ebp);
        fprintf(out_file, "\tESI:  0x%x, EDI: 0x%x\n", ptss->esi, ptss->edi);
        fprintf(out_file, "\tES:   0x%x, CS:  0x%x\n", ptss->es,  ptss->cs);
        fprintf(out_file, "\tSS:   0x%x, DS:  0x%x\n", ptss->ss,  ptss->ds);
        fprintf(out_file, "\tFS:   0x%x, GS:  0x%x\n", ptss->fs,  ptss->gs);
        fprintf(out_file, "\tLDT SS: 0x%x, T: 0x%x\n", ptss->ldt_ss, ptss->T);
        fprintf(out_file, "\tI/O Map Base Address: 0x%x\n", ptss->iomba);
    }
}

PTSS tss_ctor_load(PSYSINFO psysinfo, uint32 offset)
{
    void *addr = (void *)(psysinfo->gdt.base + 8 * offset);
    PDESCRIPTOR pdesc = (PDESCRIPTOR)addr;
    uint16 _sel = offset * 8;
    uint16 _cs = 0, _es = 0, _ss = 0, _ds = 0;
    uint32 _esp = 0;

    PTSS p_tss = calloc(1, sizeof(TSS));
    uint32 ptss = (uint32) p_tss;

    __asm
    {
        mov _cs, cs
        mov _ss, ss
        mov _es, es
        mov _ds, ds
        mov _esp, esp
    }

    p_tss->cr3 = TSS_TEST_CR3;
    p_tss->cs = _cs;
    p_tss->ss = _ss;
    p_tss->ds = _ds;
    p_tss->es = _es;
    p_tss->esp = _esp;
    p_tss->eax = 0x12345678;

    pdesc->desc.limit_low = (TSS_LIMIT & 0xFFFF);
    pdesc->desc.base_low = (ptss & 0xFFFF);
    pdesc->desc.base_mid = (ptss >> 16) & 0xFF;
    pdesc->desc.type = 0x9;
    pdesc->desc.s = 0;
    pdesc->desc.dpl = 0;
    pdesc->desc.p = 1;
    pdesc->desc.limit_high = (TSS_LIMIT >> 16) & 0xFF;
    pdesc->desc.avl = 0;
    pdesc->desc.rsrvd = 0;
    pdesc->desc.db = 0;
    pdesc->desc.g = 0;
    pdesc->desc.base_high = (ptss >> 24) & 0xFF;

    __asm
    {
        push ax
        mov ax, _sel
        ltr ax
        pop ax
    }

    return p_tss;
}

void tss_dtor(PTSS p_tss)
{
    free(p_tss);
}

void main()
{
    FILE* out_file = fopen("B:\\OUT.TXT", "w");
    PTSS ptss = NULL;
    if (out_file == NULL)
    {
        printf("Cannot open out_file\n");
        return;
    }

    printf("Hello, world! \n");
    get_sysinfo(&sysinfo);

    printf("================ \n");
    printf("GDT: base=0x%08X limit=0x%04X \n", sysinfo.gdt.base, sysinfo.gdt.limit);
    printf("IDT: base=0x%08X limit=0x%04X \n", sysinfo.idt.base, sysinfo.idt.limit);
    printf("LDT: selector=0x%04X \n", sysinfo.ldt.raw);
    printf("TSS: selector=0x%04X \n", sysinfo.tr.raw);

    ptss = tss_ctor_load(&sysinfo, TSS_IDX);
    get_sysinfo(&sysinfo);
    tss_dump(out_file, &sysinfo);
    tss_dtor(ptss);

    gdt_dump(out_file, &sysinfo);
    idt_dump(out_file, &sysinfo);
    ldt_dump(out_file, &sysinfo);

    tss_dump(out_file, &sysinfo);
}
