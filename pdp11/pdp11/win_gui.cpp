#include "win_gui.hpp"

HWND hMainWnd;
HWND hScreen;
HWND hCaMe;
HWND hSync;
HWND hConv;
HWND hRegs[RegAm];
HWND hFlags[FlAm];
HWND hBP;

HWND hRAMListBox;
HWND hRAMListBoxDescr;
HWND hVRAMListBox;
HWND hVRAMListBoxDescr;
HWND hROMListBox;
HWND hROMListBoxDescr;
HWND hIOListBox;
HWND hIOListBoxDescr;


HBITMAP hbmp;



void upd_proc_state(const uint16_t regs[8], const status_flags flags, const uint8_t flag_I, const uint16_t bp)
{
    wchar_t buffer[64];
    char c_buffer[64];
    // go with regs
    for (uint8_t i = 0; i < RegAm; i++)
    {
        sprintf_s(c_buffer, 64, "%06o", regs[i]);
        SetWindowTextA(hRegs[i], c_buffer);
    }

    //bp
    sprintf_s(c_buffer, 64, "%06o", bp);
    SetWindowTextA(hBP, c_buffer);

    // go with flags
    if (flags.T)
        SetWindowText(hFlags[0], L"1");
    else
        SetWindowText(hFlags[0], L"0");
        
    if (flags.N)
        SetWindowText(hFlags[1], L"1");
    else
        SetWindowText(hFlags[1], L"0");
    
    if (flags.Z)
        SetWindowText(hFlags[2], L"1");
    else
        SetWindowText(hFlags[2], L"0");

    if (flags.V)
        SetWindowText(hFlags[3], L"1");
    else
        SetWindowText(hFlags[3], L"0");

    if (flags.C)
        SetWindowText(hFlags[4], L"1");
    else
        SetWindowText(hFlags[4], L"0");

    wsprintfW(buffer, L"%u", flag_I);
    SetWindowText(hFlags[5], buffer);

}


void print_disasm(char str_arr[ROM_size / 2][100])
{
    SendMessage(hROMListBox, WM_SETREDRAW, FALSE, 0L);
    SetWindowText(hROMListBoxDescr, L"ROM (disasm)");
    //wchar_t ListWriteBuf[max_dasm_str_length];

    // let's delete all strings and fill then
    SendMessage(hROMListBox, LB_RESETCONTENT, 0, 0);

    for (int i = 0; i < ROM_size / 2; i++)
    {
        SendMessageA(hROMListBox, LB_ADDSTRING, 0,
            (LPARAM)str_arr[i]);
    }

    SendMessage(hROMListBox, WM_SETREDRAW, TRUE, 0L);
    InvalidateRect(hROMListBox, NULL, TRUE);
}


void print_memory(char str_arr1[RAM_size / 2][100], char str_arr2[VRAM_size / 2][100], char str_arr3[IO_size / 2][100])
{
    print_RAM(str_arr1);
    print_VRAM(str_arr2);
    print_IO(str_arr3);
}


void print_RAM(char str_arr[RAM_size / 2][100])
{
    SendMessage(hRAMListBox, WM_SETREDRAW, FALSE, 0L);
    SetWindowText(hRAMListBoxDescr, L"RAM");
    //wchar_t ListWriteBuf[max_dasm_str_length];

    // let's delete all strings and fill then
    SendMessage(hRAMListBox, LB_RESETCONTENT, 0, 0);

    for(int i = 0; i < RAM_size / 2; i++)
    {
        SendMessageA(hRAMListBox, LB_ADDSTRING, 0,
            (LPARAM)str_arr[i]);
    }

    SendMessage(hRAMListBox, WM_SETREDRAW, TRUE, 0L);
    InvalidateRect(hRAMListBox, NULL, TRUE);
}


void print_VRAM(char str_arr[VRAM_size / 2][100])
{
    SendMessage(hVRAMListBox, WM_SETREDRAW, FALSE, 0L);
    SetWindowText(hVRAMListBoxDescr, L"VRAM");
    //wchar_t ListWriteBuf[max_dasm_str_length];

    // let's delete all strings and fill then
    SendMessage(hVRAMListBox, LB_RESETCONTENT, 0, 0);

    for(int i = 0; i < VRAM_size / 2; i++)
    {
        SendMessageA(hVRAMListBox, LB_ADDSTRING, 0,
            (LPARAM)str_arr[i]);
    }

    SendMessage(hVRAMListBox, WM_SETREDRAW, TRUE, 0L);
    InvalidateRect(hVRAMListBox, NULL, TRUE);
}


void print_IO(char str_arr[IO_size / 2][100])
{
    SendMessage(hIOListBox, WM_SETREDRAW, FALSE, 0L);
    SetWindowText(hIOListBoxDescr, L"IO");
    //wchar_t ListWriteBuf[max_dasm_str_length];

    // let's delete all strings and fill then
    SendMessage(hIOListBox, LB_RESETCONTENT, 0, 0);

    for(int i = 0; i < IO_size / 2; i++)
    {
        SendMessageA(hIOListBox, LB_ADDSTRING, 0,
            (LPARAM)str_arr[i]);
    }

    SendMessage(hIOListBox, WM_SETREDRAW, TRUE, 0L);
    InvalidateRect(hIOListBox, NULL, TRUE);
}


void get_octal_wstr(char* buff, uint16_t n)
{
    uint16_t temp = n;
    for (int i = 0; i < 6; i++)
    {
        buff[5 - i] = '0' + (char)(temp % 8);
        temp = static_cast<uint16_t>(temp / 8);
    }
    buff[6] = 0;
}


LRESULT CALLBACK WindowProcedure(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    wchar_t buffer_g[256];
    pdp11* the_pdp11 = nullptr;
    VRet checkErr;
    LRESULT res;
    LRESULT count;
    uint16_t iSelected;
    uint8_t key_code = 0;

    if(msg == WM_CREATE)
    {
        LPCREATESTRUCT pCreate = reinterpret_cast<LPCREATESTRUCT>(lp);
        the_pdp11 = reinterpret_cast<pdp11*>(pCreate->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)the_pdp11);
    }
    else
    {
        LONG_PTR ptr = GetWindowLongPtrW(hWnd, GWLP_USERDATA);
        the_pdp11 = reinterpret_cast<pdp11*>(ptr);
    }

    wchar_t msg2[32];

    switch (msg)
    {
    case WM_CREATE:
        add_controls(hWnd);
        break;


    case WM_KEYDOWN:
        swprintf_s(msg2, L"WM_KEYDOWN: 0x%x\n", wp);
        OutputDebugString(msg2);

        key_code = static_cast<uint8_t>(wp);
        the_pdp11->set_key_code(key_code);

        the_pdp11->do_job(pdp_job_type::IRQ01);

        return DefWindowProc(hWnd, msg, wp, lp);
        break;


    case WM_COMMAND:
        switch(LOWORD(wp))
        {
        case RUN_BUTTON:
            checkErr = the_pdp11->do_job(pdp_job_type::RUN);
            if(checkErr != VRet::VSUCCESS)
            {
                if (checkErr == VRet::VFAILURE)
                    MessageBoxW(GetConsoleWindow(), L"Pdp-11 is already running.", 0, MB_ICONSTOP | MB_TASKMODAL);
                else
                    MessageBoxW(GetConsoleWindow(), L"The task is already queued up.", 0, MB_ICONINFORMATION | MB_TASKMODAL);

                return 0;
            }
            break;

        case EXIT_BUTTON:
            checkErr = the_pdp11->do_job(pdp_job_type::EXIT);
            if(checkErr != VRet::VSUCCESS)
            {
                MessageBoxW(GetConsoleWindow(), L"Pdp-11 is already running.", 0, MB_ICONSTOP | MB_TASKMODAL);
                return 0;
            }

            DestroyWindow(hWnd);
            break;

        case INPUT_BUTTON:
            MessageBoxW(GetConsoleWindow(), L"\tinput\t\t", L"input", MB_ICONINFORMATION | MB_TASKMODAL);
            break;

        case LOAD_EXE_BUTTON:
            checkErr = the_pdp11->do_job(pdp_job_type::LOAD);
            if(checkErr != VRet::VSUCCESS)
            {
                MessageBoxW(GetConsoleWindow(), L"Pdp-11 is already running.", 0, MB_ICONSTOP | MB_TASKMODAL);
            }
            break;

        case LOAD_MEM_BUTTON:
            the_pdp11->load_mem();
            break;

        case LOAD_REGS_BUTTON:
            the_pdp11->load_regs();
            break;

        case RESET_BUTTON:
            checkErr = the_pdp11->do_job(pdp_job_type::RESET);
            if(checkErr != VRet::VSUCCESS)
            {
                MessageBoxW(GetConsoleWindow(), L"Pdp-11 is already running.", 0, MB_ICONSTOP | MB_TASKMODAL);
            }
            break;


        case BREAKPOINT_BUTTON:
            checkErr = the_pdp11->set_bp();
            if(checkErr != VRet::VSUCCESS)
            {
                MessageBoxW(GetConsoleWindow(), L"Select failure", 0, MB_ICONSTOP | MB_TASKMODAL);
                return 0;
            }

            the_pdp11->load_regs();
            break;

        case syncID:
            res = SendMessage(hSync, BM_GETCHECK, 0, 0);

            if(res == BST_CHECKED)
            {
                sync_on(the_pdp11);
            }
            if(res == BST_UNCHECKED)
            {
                sync_off(the_pdp11);
            }
            break;


        case CaMeID:
            res = SendMessage(hCaMe, BM_GETCHECK, 0, 0);

            if (res == BST_CHECKED)
            {
                cache_mem_on(the_pdp11);
            }
            if (res == BST_UNCHECKED)
            {
                cache_mem_off(the_pdp11);
            }
            break;

        case ConvID:
            res = SendMessage(hConv, BM_GETCHECK, 0, 0);

            if (res == BST_CHECKED)
            {
                conv_on(the_pdp11);
            }
            if (res == BST_UNCHECKED)
            {
                conv_off(the_pdp11);
            }
            break;

        case rom_list_id:
            switch (HIWORD(wp))
            {
            case LBN_SELCHANGE:
                count = SendMessage(hROMListBox, LB_GETCOUNT, 0, 0);
                iSelected = 0;

                // go through the items and find the first selected one
                for(LRESULT i = 0; i < count; i++)
                {
                    // check if this item is selected or not..
                    if(SendMessage(hROMListBox, LB_GETSEL, static_cast<WPARAM>(i), 0) > 0)
                    {
                        // yes, we only want the first selected so break.
                        iSelected = static_cast<uint16_t>(i);
                        break;
                    }
                }

                wsprintfW(buffer_g, L"ROM (disasm), selected %d", iSelected);
                SetWindowText(hROMListBoxDescr, buffer_g);
                the_pdp11->set_selected(iSelected);
                break;
            }
            break;
            

        default:
            break;
        }

        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, msg, wp, lp);
    }
    //https://docs.microsoft.com/en-us/windows/win32/winmsg/using-window-procedures
    return 0;
}


void add_controls(HWND hWnd)
{
    hScreen = CreateWindowW(L"Static", NULL, WS_VISIBLE | WS_CHILD | SS_BITMAP | WS_BORDER, pdp_win_x, pdp_win_y, pdp_win_width, pdp_win_height,
        hWnd, NULL, NULL, NULL);
    // Vadik buttons
    CreateWindowW(L"Button", L"Run",
        WS_VISIBLE | WS_CHILD,
        run_x, run_y, button_width, button_height,
        hWnd, (HMENU)RUN_BUTTON, NULL, NULL);

    CreateWindowW(L"Button", L"Exit",
        WS_VISIBLE | WS_CHILD,
        exit_x, exit_y, button_width, button_height,
        hWnd, (HMENU)EXIT_BUTTON, NULL, NULL);

    CreateWindowW(L"Button", L"Input",
        WS_VISIBLE | WS_CHILD,
        input_x, input_y, button_width, button_height,
        hWnd, (HMENU)INPUT_BUTTON, NULL, NULL);

    CreateWindowW(L"Button", L"Load exe",
        WS_VISIBLE | WS_CHILD,
        load_exe_x, load_exe_y, button_width, button_height,
        hWnd, (HMENU)LOAD_EXE_BUTTON, NULL, NULL);

    CreateWindowW(L"Button", L"Load mem",
        WS_VISIBLE | WS_CHILD,
        load_mem_x, load_mem_y, button_width, button_height,
        hWnd, (HMENU)LOAD_MEM_BUTTON, NULL, NULL);

    CreateWindowW(L"Button", L"Load regs",
        WS_VISIBLE | WS_CHILD,
        load_regs_flags_x, load_regs_flags_y, button_width, button_height,
        hWnd, (HMENU)LOAD_REGS_BUTTON, NULL, NULL);

    CreateWindow(L"Button", L"Reset",
        WS_VISIBLE | WS_CHILD,
        reset_x , reset_y, button_width, button_height,
        hWnd, (HMENU)RESET_BUTTON, NULL, NULL);
    CreateWindow(L"Button", L"Step",
        WS_VISIBLE | WS_CHILD,
        step_x, step_y, button_width, button_height,
        hWnd, (HMENU)ReID, NULL, NULL);
    CreateWindow(L"Button", L"Stop",
        WS_VISIBLE | WS_CHILD,
        stop_x, stop_y, button_width, button_height,
        hWnd, (HMENU)STOP_BUTTON, NULL, NULL);
    CreateWindow(L"Button", L"BreakPoint",
        WS_VISIBLE | WS_CHILD ,
        breakpoint_x, breakpoint_y, button_width, button_height,
        hWnd, (HMENU)BREAKPOINT_BUTTON, NULL, NULL);

    // Check boxes (cache mem/conv)

    hSync = CreateWindow(TEXT("button"), TEXT("synchronization"),
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        synchronization_x, synchronization_y, button_width+30, button_height,
        hWnd, (HMENU)syncID, NULL, NULL);
    hCaMe = CreateWindow(TEXT("button"), TEXT("cache"),
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        cache_x, cache_y, button_width, button_height,
        hWnd, (HMENU)CaMeID, NULL, NULL);
    hConv = CreateWindow(TEXT("button"), TEXT("pipeline"),
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        pipeline_x, pipeline_y, button_width, button_height,
        hWnd, (HMENU)ConvID, NULL, NULL);

    // Text firlds with registers
    // Field with description for reg 

    wchar_t buffer[4];
    for (uint8_t i = 0; i < RegAm; i++)
    {
        wsprintfW(buffer, L"R%d", i);
        CreateWindowW(TEXT("static"), buffer,
            WS_VISIBLE | WS_CHILD | WS_BORDER ,
            RegX, RegY + (RegFieldH + RegFGap) * i, RegFieldW, RegFieldH,
            hWnd, (HMENU)(R0ID + i + getDescrID), NULL, NULL);
    }
    // Field with description for flags 
    for (uint8_t i = 0; i < FlAm; i++)
    {
        CreateWindow(TEXT("static"), Flags[i],
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            RegX, RegY + (RegFieldH + RegFGap) * (i + RegAm), RegFieldW, RegFieldH,
            hWnd, (HMENU)(FiFlID + i + getDescrID), NULL, NULL);
    }

    CreateWindow(TEXT("static"), L"bp",
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            RegX, RegY - (RegFieldH + RegFGap) , RegFieldW, RegFieldH,
            hWnd, (HMENU)bpDid, NULL, NULL);

    // Fields with values for regs
    for (uint8_t i = 0; i < RegAm; i++)
    {
        hRegs[i] = CreateWindow(TEXT("static"), TEXT("000000"),
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            RegX + RegFieldW + RegFGap, RegY + (RegFieldH + RegFGap) * i, RegValFieldW, RegFieldH,
            hWnd, (HMENU)(R0ID + i), NULL, NULL);

    }
    // Fields with values for regs
    for (uint8_t i = 0; i < FlAm; i++)
    {
        hFlags[i] = CreateWindow(TEXT("static"), TEXT("0"),
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            RegX + RegFieldW + RegFGap, RegY + (RegFieldH + RegFGap) * (i + RegAm), RegValFieldW, RegFieldH,
            hWnd, (HMENU)(FiFlID + i), NULL, NULL);
    }

    hBP = CreateWindow(TEXT("static"), L"000000",
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        RegX + RegFieldW + RegFGap, RegY - (RegFieldH + RegFGap), RegValFieldW, RegFieldH,
        hWnd, (HMENU)bpid, NULL, NULL);

    // list
    hRAMListBoxDescr = CreateWindow(TEXT("static"), TEXT("RAM"),
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        ram_x, ram_y, desc_box_width, desc_box_height,
        hWnd, (HMENU)(ram_list_id + getDescrID), NULL, NULL);

    hRAMListBox = CreateWindow(L"listbox", NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD |
        LBS_WANTKEYBOARDINPUT,
        ram_x, ram_y + desc_box_height + list_descr_offset, list_box_width, list_box_height,
        hWnd, (HMENU)ram_list_id, NULL, NULL);


    hVRAMListBoxDescr = CreateWindow(TEXT("static"), TEXT("VRAM"),
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        vram_x, vram_y, desc_box_width, desc_box_height,
        hWnd, (HMENU)(vram_list_id + getDescrID), NULL, NULL);

    hVRAMListBox = CreateWindow(L"listbox", NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD |
        LBS_WANTKEYBOARDINPUT,
        vram_x, vram_y + desc_box_height + list_descr_offset, list_box_width, list_box_height,
        hWnd, (HMENU)vram_list_id, NULL, NULL);


    hROMListBoxDescr = CreateWindow(TEXT("static"), TEXT("ROM (disasm)"),
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        rom_x, rom_y, desc_box_width, desc_box_height,
        hWnd, (HMENU)(rom_list_id + getDescrID), NULL, NULL);

    hROMListBox = CreateWindow(L"listbox", NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD |
        LBS_WANTKEYBOARDINPUT,
        rom_x, rom_y + desc_box_height + list_descr_offset, list_box_width, list_box_height,
        hWnd, (HMENU)rom_list_id, NULL, NULL);
    
    
    hIOListBoxDescr = CreateWindow(TEXT("static"), TEXT("IO"),
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        io_x, io_y, desc_box_width, desc_box_height,
        hWnd, (HMENU)(io_list_id + getDescrID), NULL, NULL);

    hIOListBox = CreateWindow(L"listbox", NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD |
        LBS_WANTKEYBOARDINPUT,
        io_x, io_y + desc_box_height + list_descr_offset, list_box_width, list_box_height,
        hWnd, (HMENU)io_list_id, NULL, NULL);
}


void DrawPixels(HWND hscr, void *pixels)
{
    hbmp = CreateBitmap(512, 512, 1, 32, pixels);
    SendMessageW(hscr, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hbmp);
}


bool gui_open_file(char *out_str)
{
    OPENFILENAMEA ofn;

    ZeroMemory(&ofn, sizeof(OPENFILENAME));

    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFile = out_str;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = 100;
    ofn.lpstrFilter = "Text files\0*.txt\0";
    ofn.nFilterIndex = 1;

    return GetOpenFileNameA(&ofn);
}
