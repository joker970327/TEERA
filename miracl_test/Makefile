# 可配置的选项列表
PAIRING_TESTS = CP80 MNT80 BN128 BN192 KSS192 BLS256

CPP_DEPENDENCIES = \
    CP80:miracl_test.cpp;../cp_pair.cpp;../zzn2.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp\
    MNT80:miracl_test.cpp;../mnt_pair.cpp;../zzn6a.cpp;../ecn3.cpp;../zzn3.cpp;../zzn2.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp \
    BN128:miracl_test.cpp;../bn_pair.cpp;../zzn12a.cpp;../ecn2.cpp;../zzn4.cpp;../zzn2.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp \
    BN192:miracl_test.cpp;../bn_pair.cpp;../zzn12a.cpp;../ecn2.cpp;../zzn4.cpp;../zzn2.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp \
    KSS192:miracl_test.cpp;../kss_pair.cpp;../zzn18.cpp;../zzn6.cpp;../ecn3.cpp;../zzn3.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp \
    BLS256:miracl_test.cpp;../bls_pair.cpp;../zzn24.cpp;../zzn8.cpp;../zzn4.cpp;../zzn2.cpp;../ecn4.cpp;../../big.cpp;../../zzn.cpp;../../ecn.cpp

# $1表示第一个参数，这个函数筛选出以第一个参数开头的行
get_dependency = $(subst ;, ,$(patsubst $1:%,%,$(filter $1:%,$(CPP_DEPENDENCIES))))

# 设置编译器和编译选项
CXX = g++
CXXFLAGS = -O2 
# 如果你的编译器需要显式开启 rdtsc 支持
# CXXFLAGS += -mrdtscmake

# 构建目标的基础名字
TARGET_BASE = test

# 定义构建目标和依赖
all: $(foreach FILE,$(PAIRING_TESTS),$(TARGET_BASE)_$(FILE).out)

# 通用目标构建规则
$(TARGET_BASE)_%.out:
	$(CXX) $(CXXFLAGS) -DPAIRING_$*_TEST -o $@ $(call get_dependency,$*) -L./ ../miracl.a -I ../ -I ../../

# 清理规则
clean:
	rm -f $(foreach FILE,$(PAIRING_TESTS),$(TARGET_BASE)_$(FILE).out)
	rm -f *.out