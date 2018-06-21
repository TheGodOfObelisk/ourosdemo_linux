#include "base.h"
#include <iostream>
static const char *program_name = NULL;

void set_program_name(const char *name){
	std::cout<<"here is base.cpp"<<std::endl;
	program_name = name;
}
