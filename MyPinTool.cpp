/*
Name: Konchady Gaurav Shenoy
NETID: KXS168430
Course: CS 6332.501 - Systems Security and Malicious Code Analysis
Instructor: Dr. Zhiqiang Lin
Project #1 - Execution Tracing w/ Dynamic Binary Instrumentation
Date of Submission: September 17 2017
*/

//#include "pin.H"
//#include <iostream>
//#include <fstream>

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "pin.H"
#include "control_manager.H"

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

using namespace CONTROLLER;


/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 static insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread

UINT64 icount = 0;

//std::ostream * out = &cerr;
//std::ofstream* out;
ofstream OutFile;
std::ofstream TraceFile_inscnt_q1 ("MyPinTool_q1_InstructionCount.out", std::ofstream::out);
std::ofstream Img_OutFile ("MyPinTool_q2_image.out", std::ofstream::out);
std::ofstream TraceFile_malloc_q5 ("MyPinTool_q5_malloc.out", std::ofstream::out);
std::ofstream TraceFile_strace_q4 ("MyPinTool_q4_fcalls.out", std::ofstream::out);
std::ofstream TraceFile_opcodecnt_q3 ("MyPinTool_q3_opcodecnt.out", std::ofstream::out);
std::ofstream q6 ("MyPinTool_q6_strace.out", std::ofstream::out);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
//    "o", "MyPinTool.out", "specify file name for MyPinTool output");
//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
//    "o", "MYPinTool_3.out", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


//Q3
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
    "o", "MYPintool_q3_opcodemix.out", "specify profile file name");
KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "0", "append pid to output");
KNOB<BOOL>   KnobProfilePredicated(KNOB_MODE_WRITEONCE,  "pintool",
    "p", "0", "enable accurate profiling for predicated instructions");
KNOB<BOOL>   KnobProfileStaticOnly(KNOB_MODE_WRITEONCE,  "pintool",
    "s", "0", "terminate after collection of static profile for main image");
#ifndef TARGET_WINDOWS
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "0", "Only collect dynamic profile");
#else
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "1", "Only collect dynamic profile");
#endif
KNOB<BOOL>   KnobNoSharedLibs(KNOB_MODE_WRITEONCE,       "pintool",
    "no_shared_libs", "0", "do not instrument shared libraries");

//Q4
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments ");
string invalid = "invalid_rtn";


/* ===================================================================== */
/* INDEX HELPERS */
/* ===================================================================== */

const UINT32 MAX_INDEX = 4096;
const UINT32 INDEX_SPECIAL =  3000;
const UINT32 MAX_MEM_SIZE = 512;


const UINT32 INDEX_TOTAL =          INDEX_SPECIAL + 0;
const UINT32 INDEX_MEM_ATOMIC =     INDEX_SPECIAL + 1;
const UINT32 INDEX_STACK_READ =     INDEX_SPECIAL + 2;
const UINT32 INDEX_STACK_WRITE =    INDEX_SPECIAL + 3;
const UINT32 INDEX_IPREL_READ =     INDEX_SPECIAL + 4;
const UINT32 INDEX_IPREL_WRITE =    INDEX_SPECIAL + 5;
const UINT32 INDEX_MEM_READ_SIZE =  INDEX_SPECIAL + 6;
const UINT32 INDEX_MEM_WRITE_SIZE = INDEX_SPECIAL + 6 + MAX_MEM_SIZE;
const UINT32 INDEX_SPECIAL_END   =  INDEX_SPECIAL + 6 + MAX_MEM_SIZE + MAX_MEM_SIZE;


BOOL IsMemReadIndex(UINT32 i)
{
    return (INDEX_MEM_READ_SIZE <= i && i < INDEX_MEM_READ_SIZE + MAX_MEM_SIZE );
}

BOOL IsMemWriteIndex(UINT32 i)
{
    return (INDEX_MEM_WRITE_SIZE <= i && i < INDEX_MEM_WRITE_SIZE + MAX_MEM_SIZE );
}


/* ===================================================================== */

LOCALFUN UINT32 INS_GetIndex(INS ins)
{
    if( INS_IsPredicated(ins) )
        return MAX_INDEX + INS_Opcode(ins);
    else
        return INS_Opcode(ins);
}

/* ===================================================================== */

LOCALFUN  UINT32 IndexStringLength(BBL bbl, BOOL memory_acess_profile)
{
    UINT32 count = 0;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
        count++;
        if( memory_acess_profile )
        {
            if( INS_IsMemoryRead(ins) ) count++;   // for size

            if( INS_IsStackRead(ins) ) count++;

            if( INS_IsIpRelRead(ins) ) count++;


            if( INS_IsMemoryWrite(ins) ) count++; // for size

            if( INS_IsStackWrite(ins) ) count++;

            if( INS_IsIpRelWrite(ins) ) count++;


            if( INS_IsAtomicUpdate(ins) ) count++;
        }
    }

    return count;
}


/* ===================================================================== */
LOCALFUN UINT32 MemsizeToIndex(UINT32 size, BOOL write)
{
    return (write ? INDEX_MEM_WRITE_SIZE : INDEX_MEM_READ_SIZE ) + size;
}

/* ===================================================================== */
LOCALFUN UINT16 *INS_GenerateIndexString(INS ins, UINT16 *stats, BOOL memory_acess_profile)
{
    *stats++ = INS_GetIndex(ins);

    if( memory_acess_profile )
    {
        if( INS_IsMemoryRead(ins) )  *stats++ = MemsizeToIndex( INS_MemoryReadSize(ins), 0 );
        if( INS_IsMemoryWrite(ins) ) *stats++ = MemsizeToIndex( INS_MemoryWriteSize(ins), 1 );

        if( INS_IsAtomicUpdate(ins) ) *stats++ = INDEX_MEM_ATOMIC;

        if( INS_IsStackRead(ins) ) *stats++ = INDEX_STACK_READ;
        if( INS_IsStackWrite(ins) ) *stats++ = INDEX_STACK_WRITE;

        if( INS_IsIpRelRead(ins) ) *stats++ = INDEX_IPREL_READ;
        if( INS_IsIpRelWrite(ins) ) *stats++ = INDEX_IPREL_WRITE;
    }

    return stats;
}


/* ===================================================================== */

LOCALFUN string IndexToOpcodeString( UINT32 index )
{
    if( INDEX_SPECIAL <= index  && index < INDEX_SPECIAL_END)
    {
        if( index == INDEX_TOTAL )            return  "*total";
        else if( IsMemReadIndex(index) )      return  "*mem-read-" + decstr( index - INDEX_MEM_READ_SIZE );
        else if( IsMemWriteIndex(index))      return  "*mem-write-" + decstr( index - INDEX_MEM_WRITE_SIZE );
        else if( index == INDEX_MEM_ATOMIC )  return  "*mem-atomic";
        else if( index == INDEX_STACK_READ )  return  "*stack-read";
        else if( index == INDEX_STACK_WRITE ) return  "*stack-write";
        else if( index == INDEX_IPREL_READ )  return  "*iprel-read";
        else if( index == INDEX_IPREL_WRITE ) return  "*iprel-write";

        else
        {
            ASSERTX(0);
            return "";
        }
    }
    else
    {
        return OPCODE_StringShort(index);
    }

}

/* ===================================================================== */
/* ===================================================================== */
typedef UINT64 COUNTER;


/* zero initialized */

class STATS
{
  public:
    COUNTER unpredicated[MAX_INDEX];
    COUNTER predicated[MAX_INDEX];
    COUNTER predicated_true[MAX_INDEX];

    VOID Clear()
    {
        for ( UINT32 i = 0; i < MAX_INDEX; i++)
        {
            unpredicated[i] = 0;
            predicated[i] = 0;
            predicated_true[i] = 0;
        }
    }
};


STATS GlobalStatsStatic;
STATS GlobalStatsDynamic;

class BBLSTATS
{
  public:
    COUNTER _counter;
    const UINT16 * const _stats;

  public:
    BBLSTATS(UINT16 * stats) : _counter(0), _stats(stats) {};

};



LOCALVAR vector<const BBLSTATS*> statsList;



/* ===================================================================== */

LOCALVAR UINT32 enabled = 0;

LOCALFUN VOID Handler(EVENT_TYPE ev, VOID *val, CONTEXT * ctxt, VOID *ip, THREADID tid, bool bcast)
{
    switch(ev)
    {
      case EVENT_START:
        enabled = 1;
        break;

      case EVENT_STOP:
        enabled = 0;
        break;

      default:
        ASSERTX(false);
    }
}


LOCALVAR CONTROL_MANAGER control;

/* ===================================================================== */

VOID PIN_FAST_ANALYSIS_CALL docount(COUNTER * counter)
{
    (*counter) += enabled;
}

/* ===================================================================== */
// Utilities
/* ===================================================================== */

// This function is called before every instruction is executed
VOID docount() { icount++; }
    
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}


VOID ImageLoad(IMG img, VOID *v)
{
    Img_OutFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
    //cerr << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
}


/* ===================================================================== */

VOID Trace1(TRACE trace, VOID *v)
{
    if ( KnobNoSharedLibs.Value()
         && IMG_Type(SEC_Img(RTN_Sec(TRACE_Rtn(trace)))) == IMG_TYPE_SHAREDLIB)
        return;

    const BOOL accurate_handling_of_predicates = KnobProfilePredicated.Value();

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        const INS head = BBL_InsHead(bbl);
        if (! INS_Valid(head)) continue;

        // Summarize the stats for the bbl in a 0 terminated list
        // This is done at instrumentation time
        const UINT32 n = IndexStringLength(bbl, 1);

        UINT16 *const stats = new UINT16[ n + 1];
        UINT16 *const stats_end = stats + (n + 1);
        UINT16 *curr = stats;

        for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
        {
            // Count the number of times a predicated instruction is actually executed
            // this is expensive and hence disabled by default
            if( INS_IsPredicated(ins) && accurate_handling_of_predicates )
            {
                INS_InsertPredicatedCall(ins,
                                         IPOINT_BEFORE,
                                         AFUNPTR(docount),
                                         IARG_PTR, &(GlobalStatsDynamic.predicated_true[INS_Opcode(ins)]),
                                         IARG_END);
            }

            curr = INS_GenerateIndexString(ins,curr,1);
        }

        // string terminator
        *curr++ = 0;

        ASSERTX( curr == stats_end );


        // Insert instrumentation to count the number of times the bbl is executed
        BBLSTATS * bblstats = new BBLSTATS(stats);
        INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(bblstats->_counter), IARG_END);

        // Remember the counter and stats so we can compute a summary at the end
        statsList.push_back(bblstats);
    }
}

VOID DumpStats(ofstream& out, STATS& stats, BOOL predicated_true,  const string& title)
{
    out <<
        "#\n"
        "# " << title << "\n"
        "#\n"
        "#     opcode       count-unpredicated    count-predicated";

    if( predicated_true )
        out << "    count-predicated-true";

    out << "\n#\n";

    for ( UINT32 i = 0; i < INDEX_TOTAL; i++)
    {
        stats.unpredicated[INDEX_TOTAL] += stats.unpredicated[i];
        stats.predicated[INDEX_TOTAL] += stats.predicated[i];
        stats.predicated_true[INDEX_TOTAL] += stats.predicated_true[i];
    }

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        if( stats.unpredicated[i] == 0 &&
            stats.predicated[i] == 0 ) continue;

        out << setw(4) << i << " " <<  ljstr(IndexToOpcodeString(i),15) << " " <<
            setw(16) << stats.unpredicated[i] << " " <<
            setw(16) << stats.predicated[i];
        if( predicated_true ) out << " " << setw(16) << stats.predicated_true[i];
        out << endl;
    }
}

/* ===================================================================== */


// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
               ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_IA32) 
    // On ia32, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = &arg0;
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif
     switch(num)
     {
case 1: 
		q6 << "@ip 0x" << hex << ip << ": sys call exit with number= " << dec << num<<endl;
		break;
case 2: 
		q6 << "@ip 0x" << hex << ip << ": sys call fork with number= " << dec << num<<endl;
		break;
case 3: 
		q6 << "@ip 0x" << hex << ip << ": sys call read with number= " << dec << num<<endl;
		break;
case 4: 
		q6 << "@ip 0x" << hex << ip << ": sys call write with number= " << dec << num<<endl;
		break;
case 5: 
		q6 << "@ip 0x" << hex << ip << ": sys call open with number= " << dec << num<<endl;
		break;
case 6: 
		q6 << "@ip 0x" << hex << ip << ": sys call close with number= " << dec << num<<endl;
		break;
case 7: 
		q6 << "@ip 0x" << hex << ip << ": sys call waitpid with number= " << dec << num<<endl;
		break;
case 8: 
		q6 << "@ip 0x" << hex << ip << ": sys call creat with number= " << dec << num<<endl;
		break;
case 9: 
		q6 << "@ip 0x" << hex << ip << ": sys call link with number= " << dec << num<<endl;
		break;
case 10: 
		q6 << "@ip 0x" << hex << ip << ": sys call unlink with number= " << dec << num<<endl;
		break;
case 11: 
		q6 << "@ip 0x" << hex << ip << ": sys call execve with number= " << dec << num<<endl;
		break;
case 12: 
		q6 << "@ip 0x" << hex << ip << ": sys call chdir with number= " << dec << num<<endl;
		break;
case 13: 
		q6 << "@ip 0x" << hex << ip << ": sys call time with number= " << dec << num<<endl;
		break;
case 14: 
		q6 << "@ip 0x" << hex << ip << ": sys call mknod with number= " << dec << num<<endl;
		break;
case 15: 
		q6 << "@ip 0x" << hex << ip << ": sys call chmod with number= " << dec << num<<endl;
		break;
case 16: 
		q6 << "@ip 0x" << hex << ip << ": sys call lchown with number= " << dec << num<<endl;
		break;
case 18: 
		q6 << "@ip 0x" << hex << ip << ": sys call stat with number= " << dec << num<<endl;
		break;
case 19: 
		q6 << "@ip 0x" << hex << ip << ": sys call lseek with number= " << dec << num<<endl;
		break;
case 20: 
		q6 << "@ip 0x" << hex << ip << ": sys call getpid with number= " << dec << num<<endl;
		break;
case 21: 
		q6 << "@ip 0x" << hex << ip << ": sys call mount with number= " << dec << num<<endl;
		break;
case 22: 
		q6 << "@ip 0x" << hex << ip << ": sys call unmount with number= " << dec << num<<endl;
		break;
case 23: 
		q6 << "@ip 0x" << hex << ip << ": sys call setuid with number= " << dec << num<<endl;
		break;
case 24: 
		q6 << "@ip 0x" << hex << ip << ": sys call getuid with number= " << dec << num<<endl;
		break;
case 25: 
		q6 << "@ip 0x" << hex << ip << ": sys call stime with number= " << dec << num<<endl;
		break;
case 26: 
		q6 << "@ip 0x" << hex << ip << ": sys call ptrace with number= " << dec << num<<endl;
		break;
case 27: 
		q6 << "@ip 0x" << hex << ip << ": sys call alarm with number= " << dec << num<<endl;
		break;
case 28: 
		q6 << "@ip 0x" << hex << ip << ": sys call fstat with number= " << dec << num<<endl;
		break;
case 29: 
		q6 << "@ip 0x" << hex << ip << ": sys call pause with number= " << dec << num<<endl;
		break;
case 30: 
		q6 << "@ip 0x" << hex << ip << ": sys call utime with number= " << dec << num<<endl;
		break;
case 33: 
		q6 << "@ip 0x" << hex << ip << ": sys call access with number= " << dec << num<<endl;
		break;
case 78: 
		q6 << "@ip 0x" << hex << ip << ": sys call gettimeofday with number= " << dec << num<<endl;
		break;
case 97: 
		q6 << "@ip 0x" << hex << ip << ": sys call setpriority with number= " << dec << num<<endl;
		break;
case 137: 
		q6 << "@ip 0x" << hex << ip << ": sys call afs syscall with number= " << dec << num<<endl;
		break;
default:
		q6 << "@ip 0x" << hex << ip << ": sys call " << dec << num;
    		q6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
    		q6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
     }
    
    
}


VOID SysAfter(ADDRINT ret)
{
    //fprintf(q6,"returns: 0x%lx\n", (unsigned long)ret);
    q6 <<"returns: " << (unsigned long)ret;
    //fflush(trace);
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

VOID Instruction_q6(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);

        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE,
                       IARG_END);
    }
}

/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */

const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}

/* ===================================================================== */

VOID  do_call_args(const string *s, ADDRINT arg0)
{
    TraceFile_strace_q4 << *s << "(" << arg0 << ",...)" << endl;
}


VOID  do_call_args_indirect(ADDRINT target, BOOL taken, ADDRINT arg0)
{
    if( !taken ) return;
    
    const string *s = Target2String(target);
    do_call_args(s, arg0);

    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID  do_call(const string *s)
{
    TraceFile_strace_q4 << *s << endl;
}

/* ===================================================================== */

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
    if( !taken ) return;

    const string *s = Target2String(target);
    do_call( s );
    
    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID Trace_q4(TRACE trace, VOID *v)
{
    const BOOL print_args = KnobPrintArgs.Value();
    
        
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS tail = BBL_InsTail(bbl);
        
        if( INS_IsCall(tail) )
        {
            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                if( print_args )
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_PTR, Target2String(target), IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_PTR, Target2String(target), IARG_END);
                }
                
            }
            else
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
                
                
            }
        }
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

                }
            }
        }
        
    }
}

/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */

VOID Arg1Before(CHAR * name, ADDRINT size)
{
    TraceFile_malloc_q5 << name << "(" << size << ")" << endl;
}

/* ===================================================================== */

VOID MallocAfter(ADDRINT ret)
{
    TraceFile_malloc_q5 << "  returns " << ret << endl;
}

/* ===================================================================== */

/* ===================================================================== */

VOID MallocImage(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(mallocRtn);
    }
    
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool has 6 functions " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           threofstream OutFile;ad creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */

//std::ofstream* out1 = 0;



VOID Fini(INT32 code, VOID *v)
{
    /**out <<  "===============================================" << endl;
    *out <<  "MyPinTool analysis results: " << endl;
    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "Number of threads: " << threadCount  << endl;
    *out <<  "===============================================" << endl;*/

//Question 1 output
    TraceFile_inscnt_q1.setf(ios::showbase);
    TraceFile_inscnt_q1 <<  "======================================================" << endl;
    TraceFile_inscnt_q1 <<  "Count of how many instructions that have been executed: " << icount << endl;
    TraceFile_inscnt_q1 <<  "======================================================" << endl;
    TraceFile_inscnt_q1 <<  "Number of instructions: " << insCount  << endl;
    TraceFile_inscnt_q1 <<  "Number of basic blocks: " << bblCount  << endl;
    TraceFile_inscnt_q1 <<  "Number of threads: " << threadCount  << endl;
    TraceFile_inscnt_q1 <<  "===============================================" << endl;

//Question 2 (Direct)

//Question 3 output
    //string filename =  KnobOutputFile.Value();
    //out1 = new std::ofstream(filename.c_str());
	
	// static counts
/*	DumpStats(TraceFile_opcodecnt_q3, GlobalStatsStatic, false, "$static-counts");
	TraceFile_opcodecnt_q3 << endl;
	// dynamic Counts
	statsList.push_back(0); // add terminator marker
	    for (vector<const BBLSTATS*>::iterator bi = statsList.begin(); bi != statsList.end(); bi++)
    {
        const BBLSTATS *b = (*bi);

        if ( b == 0 ) continue;

        for (const UINT16 * stats = b->_stats; *stats; stats++)
        {
            GlobalStatsDynamic.unpredicated[*stats] += b->_counter;
        }
    }


    DumpStats(TraceFile_opcodecnt_q3, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts");

    TraceFile_opcodecnt_q3 << "# $eof" <<  endl;

    //out->close();

*/
}

static std::ofstream* out = 0;

VOID Fini_opcode(INT32 code, VOID *v)
{
	    // static counts

    DumpStats(*out, GlobalStatsStatic, false, "$static-counts");

    *out << "# $eof" <<  endl;

    // dynamic Counts

    statsList.push_back(0); // add terminator marker

    for (vector<const BBLSTATS*>::iterator bi = statsList.begin(); bi != statsList.end(); bi++)
    {
        const BBLSTATS *b = (*bi);

        if ( b == 0 ) continue;

        for (const UINT16 * stats = b->_stats; *stats; stats++)
        {
            GlobalStatsDynamic.unpredicated[*stats] += b->_counter;
        }
    }

    DumpStats(*out, GlobalStatsStatic, KnobProfilePredicated, "$dynamic-counts");

    *out << "# $eof" <<  endl;

    out->close();
}


VOID Image(IMG img, VOID * v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                UINT16 array[128];
                UINT16 *end  = INS_GenerateIndexString(ins,array,1);

                if( INS_IsPredicated(ins) )
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.predicated[ *start ]++;
                }
                else
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.unpredicated[ *start ]++;
                }
            }

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }

    if( KnobProfileStaticOnly.Value() )
    {
        Fini_opcode(0,0);
        exit(0);
    }
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{

    PIN_InitSymbols();


    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();
    OutFile.open(KnobOutputFile.Value().c_str());




    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);

    }
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See generated .out files for analysis results of each module." << endl;
    }
    cerr <<  "===============================================" << endl;

    cerr << "Developed by Konchady Gaurav Shenoy (KXS168430)" <<endl;
    cerr <<  "===============================================" << endl;
    
    //Project Code starts here

	//Q1
	
    INS_AddInstrumentFunction(Instruction, 0); 

	//Q2
	Img_OutFile << "==============================================================================="<<endl;
	Img_OutFile << "Here are the loaded images found during binary execution of "<<endl;
	Img_OutFile << "==============================================================================="<<endl;
    IMG_AddInstrumentFunction(ImageLoad, 0);  


    //out1 = new std::ofstream(filename.c_str());
    
	//Q3
	
    control.RegisterHandler(Handler, 0, FALSE);
    control.Activate();
    string filename =  KnobOutputFile.Value();
    if (KnobPid)
    {
        filename += "." + decstr(getpid());
    }
	//out = new std::ofstream(filename.c_str());
    TRACE_AddInstrumentFunction(Trace1, 0);  
    if( !KnobProfileDynamicOnly.Value() )
        IMG_AddInstrumentFunction(Image, 0);
	PIN_AddFiniFunction(Fini_opcode, 0);

    
    //Q4
    //Trace_q4 
    TraceFile_strace_q4 << hex;
    TraceFile_strace_q4.setf(ios::showbase);
    string trace_header = string("#\n"
                                 "# Call Trace Generated By Pin\n"
                                 "#\n");
    

    TraceFile_strace_q4.write(trace_header.c_str(),trace_header.size());
    TRACE_AddInstrumentFunction(Trace_q4, 0);

    //Q5
    IMG_AddInstrumentFunction(MallocImage, 0);
    

    //Q6
    //q6 = fopen("q6.out", "w");
    INS_AddInstrumentFunction(Instruction_q6, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);    


    
    PIN_AddFiniFunction(Fini, 0);

    //if( !KnobProfileDynamicOnly.Value() )
     //   IMG_AddInstrumentFunction(Image, 0);




    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */