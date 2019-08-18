#ifndef __MEMORY_H__
#define __MEMORY_H__
char* byteCompare(char* ptr, size_t size, const std::string& pattern, const std::string& mask, int find);
char* ptrScan(const std::string& pattern, uintptr_t startAddress = 0, int find = 0);
char* ptrScan(const std::string& pattern, const std::string& mask, uintptr_t startAddress = 0, int find = 0);
char* virtualPtrScan(const std::string& pattern, const std::string& mask, uintptr_t startAddress = 0, int find = 0);
char* virtualPtrScan(const std::string& pattern, uintptr_t startAddress = 0, int find = 0);
char* rel(char* ptr, int offset = 3);
template<typename T> T ptrScan(const std::string& pattern, uintptr_t startAddress = 0, int find = 0)
{
	return reinterpret_cast<T>(ptrScan(pattern, startAddress, find));
}
template<typename T> T ptrScan(const std::string& pattern, const std::string& mask, uintptr_t startAddress = 0, int find = 0)
{
	return reinterpret_cast<T>(ptrScan(pattern, mask, startAddress, find));
}
template<typename T> T rel(char* ptr, int offset = 3)
{
	return reinterpret_cast<T>(rel(ptr, offset));
}
#endif // __MEMORY_H__