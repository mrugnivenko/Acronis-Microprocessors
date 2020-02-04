#include "PortSolver.hpp"


PortSolver::PortSolver() {}


FILE *PortSolver::fopen(const char* file_name, const char* mode) const
{
    FILE* file;

#ifdef PDP11_WINDOWS

    errno_t check_err1 = fopen_s(&file, file_name, mode);
    if(check_err1 || !file || errno)
    {
        this->perror("PortSolver::fopen");
        assert(false);
    }

#else 
#ifdef PDP11_LINUX
    using ::fopen;
    file = fopen(file_name, mode);
    if (!file)
    {
        this->perror("PortSolver::fopen");
        assert(false);
    }

#else
    static_assert(false);
#endif // PDP11_LINUX
#endif // PDP11_WINDOWS

    assert(file);
    return file;
}


FILE *PortSolver::fopen_dbg(const char *file_name, const char *mode) const
{
#ifdef  _DEBUG
    return this->fopen(file_name, mode);
#else
    return nullptr;
#endif //  _DEBUG
}


void PortSolver::fclose(FILE *file) const
{
    using ::fclose;
    int checkErr = fclose(file);
    if(checkErr || errno)
    {
        this->perror("PortSolver::fclose");
        assert(false);
    }
}


void PortSolver::fclose_dbg(FILE *file) const
{
#ifdef  _DEBUG
    this->fclose(file);
#endif //  _DEBUG
}


size_t PortSolver::get_file_size(FILE* file) const
{
    size_t size = 0;

    struct stat tmp;

    int fd = this->fileno(file);

    int checkErr1 = fstat(fd, &tmp);
    if(checkErr1 || errno)
    {
        this->perror("get_file_size: fstat");

        assert(false);
        exit(EXIT_FAILURE);
    }
    size = static_cast<size_t>(tmp.st_size);
    assert(size > 0);

    assert(!errno);
    return size;
}


void PortSolver::perror(const char *str) const
{
#ifdef PDP11_WINDOWS

    char buf[100] = "";
    strerror_s(buf, 100, errno);
    DBG_PRINTF("error: %s: %s\n", str, buf);

#else 
#ifdef PDP11_LINUX

    DBG_PRINTF("error: %s: %s\n", str, strerror(errno));

#else
    static_assert(false);
#endif // PDP11_LINUX
#endif // PDP11_WINDOWS
}


int PortSolver::fileno(FILE *file) const
{
    int fd = 0;
    
#ifdef PDP11_WINDOWS

    fd = _fileno(file);

#else 
#ifdef PDP11_LINUX

    using ::fileno;
    fd = fileno(file);

#else
    static_assert(false);
#endif // PDP11_LINUX
#endif // PDP11_WINDOWS   

    if(fd == -1 || errno)
    {
        this->perror("get_file_size: _fileno");
        assert(false);
    }

    return fd;
}


void PortSolver::dbg_print(const wchar_t *str) const
{ 
#ifdef PDP11_WINDOWS

    OutputDebugString(L"\n\n--------------------------------------------------------------------------------------\n");
    OutputDebugString(L"--------------------------------------------------------------------------------------\n");
    OutputDebugString(str);
    OutputDebugString(L"\n--------------------------------------------------------------------------------------\n");
    OutputDebugString(L"--------------------------------------------------------------------------------------\n\n\n");

#else
    static_assert(false);
#endif // PDP11_WINDOWS   

}
