#include <cstdio>
#include <cstdlib>


class MyClass
{
public:
    void foo();
    void class_func();

private:
    int m_data;

};


void some_func(void);



int main()
{
    MyClass obj;

    obj.foo();

    printf("Hello world!\n");
    return EXIT_SUCCESS;
}


void MyClass::foo()
{
    void (MyClass::*func)(void) = nullptr;

    
    //....


    func = &MyClass::class_func;

    (this->*func)();
}


void some_func()
{
    puts("some_func");
}


void MyClass::class_func()
{
    puts("class_func");
}