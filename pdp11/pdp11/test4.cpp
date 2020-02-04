#include "pdp11.hpp"
#include "win_gui.hpp"
#include "miniasm.hpp"

/*
const char txt_file1[] = "../res/1.txt";
const char txt_file2[] = "../res/2.txt";
const char txt_file3[] = "../res/3.txt";
const char txt_file4[] = "../res/4.txt";
const char txt_file5[] = "../res/5.txt";
const char txt_file6[] = "../res/6.txt";
const char txt_file7[] = "../res/7.txt";
const char txt_file8[] = "../res/8.txt";
const char txt_file9[] = "../res/9.txt";
const char txt_file10[] = "../res/10.txt";
const char txt_file15[] = "../res/15.txt";

const char bin_file1[] = "../res/1.bin";

const char *target_txt = txt_file6;
const char *targer_bin = bin_file1;
*/
const PortSolver solver;

FILE *dbg_log_file = nullptr;
FILE *pdp_log_file = nullptr;


void pdp_start(_In_ HINSTANCE hInstance);


DWORD WINAPI pdp_thread_function(void *ptr);
DWORD WINAPI video_thread_function(void *ptr);

extern HWND hMainWnd;


int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
    UNREFERENCED_PARAMETER(nShowCmd);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(hInstance);

    /*
    pdp_display_controller d_contr;
    d_contr.unzip_font(font8x8_basic);
    return EXIT_SUCCESS;
    */

    dbg_log_file = solver.fopen_dbg("log_file.txt", "w");
    
    pdp_start(hInstance);

    DBG_PRINTF("EXIT_SUCCESS\n");
    solver.fclose_dbg(dbg_log_file);
    
    return EXIT_SUCCESS;
}



void pdp_start(_In_ HINSTANCE hInstance)
{
    pdp11 the_pdp11;

    WNDCLASS wnd = {};

    wnd.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wnd.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wnd.hInstance = hInstance;
    wnd.lpszClassName = L"myWindowClass";
    wnd.lpfnWndProc = WindowProcedure;

    if(!RegisterClassW(&wnd))
        assert(false);

    hMainWnd = CreateWindowEx(0, wnd.lpszClassName, L"My Window", WS_POPUP,
        window_x, window_y, window_width, window_height,
        nullptr, nullptr, hInstance, reinterpret_cast<LPVOID>(&the_pdp11));

    if(!hMainWnd)
    {
        assert(false);
        return;
    }

    ShowWindow(hMainWnd, SW_MAXIMIZE);

    DWORD pdp_threadId;
    DWORD video_threadId;
    HANDLE hPdp = CreateThread(NULL, 0, pdp_thread_function, reinterpret_cast<void *>(&the_pdp11), 0, &pdp_threadId);
    HANDLE hVideo = CreateThread(NULL, 0, video_thread_function, reinterpret_cast<void *>(&the_pdp11), 0, &video_threadId);

    MSG msg = {};
    BOOL bRet;
    while((bRet = GetMessage(&msg, nullptr, 0, 0)) != 0)
    {
        if(bRet == -1)
        {
            solver.perror("GetMessage: bRet = -1");
            assert(false);
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if(hPdp)
    {
        WaitForSingleObject(hPdp, INFINITE);
        CloseHandle(hPdp);
    }

    if(hVideo)
    {
        WaitForSingleObject(hVideo, INFINITE);
        CloseHandle(hVideo);
    }
}


DWORD WINAPI pdp_thread_function(void *ptr)
{
    pdp11 *the_pdp11 = reinterpret_cast<pdp11 *>(ptr);
    assert(the_pdp11);
    the_pdp11->start();

    return 0;
}


DWORD WINAPI video_thread_function(void *ptr)
{
    pdp11 *the_pdp11 = reinterpret_cast<pdp11 *>(ptr);
    assert(the_pdp11);

    v_rgb pixels[512 * 512] = {};

    pdp_display_controller d_controller;
    d_controller.set_controller(the_pdp11, pixels);  

    while(!the_pdp11->should_exit())
    {
        d_controller.process_buff();

        DrawPixels(hScreen, pixels);
        
        Sleep(15);
    }

    return 0;
}
