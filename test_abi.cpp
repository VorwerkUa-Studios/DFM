#include <iostream>
#include <type_traits>

struct RegValueA {
    uint64_t u64;
    RegValueA() : u64(0) {}
    RegValueA(const RegValueA& o) : u64(o.u64) {}
};

struct RegValueB {
    uint64_t u64;
    RegValueB() : u64(0) {}
    RegValueB(const RegValueB& o) = default;
    RegValueB& operator=(const RegValueB& o) = default;
};

int main() {
    std::cout << "A trivially copyable: " << std::is_trivially_copyable_v<RegValueA> << std::endl;
    std::cout << "B trivially copyable: " << std::is_trivially_copyable_v<RegValueB> << std::endl;
    return 0;
}
