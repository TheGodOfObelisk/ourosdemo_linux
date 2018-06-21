#ifndef MY_SCANOPS_H
#define MY_SCANOPS_H

class ScanOps{
public:
	ScanOps();
	~ScanOps();
	int af(){return address_family;}
private:
	int address_family;
};

#endif
