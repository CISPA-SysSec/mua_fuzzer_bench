#include "pattern_list.h"
#include "mutations.h"

std::vector<std::unique_ptr<CallInstPattern>> CallInstPatterns;
std::vector<std::unique_ptr<ICmpInstPattern>> ICmpInstPatterns;
std::vector<std::unique_ptr<Pattern>> MiscInstPatterns;

void populateCallInstPatterns(bool cpp){
    CallInstPatterns.push_back(std::make_unique <PThreadPattern>());
    CallInstPatterns.push_back(std::make_unique <MallocPattern>());
    CallInstPatterns.push_back(std::make_unique <CallocPattern>());
    CallInstPatterns.push_back(std::make_unique <FGetsPattern>());
    CallInstPatterns.push_back(std::make_unique <INetAddrFailPattern>());
    CallInstPatterns.push_back(std::make_unique <PrintfPattern>());
    CallInstPatterns.push_back(std::make_unique <SPrintfPattern>());
    CallInstPatterns.push_back(std::make_unique <SNPrintfPattern>());
    if (cpp){
        CallInstPatterns.push_back(std::make_unique <NewArrayPattern>());
    }

}

// Add new ICmpInstPattern objects here as you add them.
void populateICmpInstPatterns(){
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanHalvedPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToHalvedPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanHalvedPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToHalvedPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanPattern>());
//    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedToUnsigned>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedToSigned>());
}

// Add new MiscInstPattern objects here as you add them.
void populateMiscInstPatterns(bool cpp){
    // also make changes to populateCallInstPatterns above if cpp-only rule also
    // applicable to "new"
    MiscInstPatterns.push_back(std::make_unique <FreeArgumentReturnPattern>());
    MiscInstPatterns.push_back(std::make_unique <CMPXCHGPattern>());
    MiscInstPatterns.push_back(std::make_unique <ATOMICRMWPattern>());
    MiscInstPatterns.push_back(std::make_unique <ShiftSwitch>());
    MiscInstPatterns.push_back(std::make_unique <UnInitLocalVariables>());
    MiscInstPatterns.push_back(std::make_unique <CompareEqualToPattern>());
    MiscInstPatterns.push_back(std::make_unique <SwitchPlusMinus>());
    MiscInstPatterns.push_back(std::make_unique <DeleteStorePattern>());
    MiscInstPatterns.push_back(std::make_unique <RedirectBranch>());
    if (cpp){
        MiscInstPatterns.push_back(std::make_unique <DeleteArgumentReturnPattern>());
    }
}

// Global function to call all the vector populators
void populatePatternVectors(bool cpp){
    populateCallInstPatterns(cpp);
    populateICmpInstPatterns();
    populateMiscInstPatterns(cpp);
}

void populatePattern(json* pattern) {
    auto patternref = *pattern;
    switch((int)patternref["type"]) {
        case MALLOC:
            CallInstPatterns.push_back(std::make_unique<MallocPattern>(pattern));
            break;
        case FGETS_MATCH_BUFFER_SIZE:
            CallInstPatterns.push_back(std::make_unique<FGetsPattern>(pattern));
            break;
        case SIGNED_LESS_THAN:
            ICmpInstPatterns.push_back(std::make_unique<SignedLessThanPattern>(pattern));
            break;
        case SIGNED_GREATER_THAN:
            ICmpInstPatterns.push_back(std::make_unique<SignedGreaterThanPattern>(pattern));
            break;
        case SIGNED_LESS_THAN_EQUALTO:
            ICmpInstPatterns.push_back(std::make_unique<SignedLessThanEqualToPattern>(pattern));
            break;
        case SIGNED_GREATER_THAN_EQUALTO:
            ICmpInstPatterns.push_back(std::make_unique<SignedGreaterThanEqualToPattern>(pattern));
            break;
        case FREE_FUNCTION_ARGUMENT:
            MiscInstPatterns.push_back(std::make_unique<FreeArgumentReturnPattern>(pattern));
            break;
        case PTHREAD_MUTEX:
            CallInstPatterns.push_back(std::make_unique<PThreadPattern>(pattern));
            break;
        case ATOMIC_CMP_XCHG:
            MiscInstPatterns.push_back(std::make_unique<CMPXCHGPattern>(pattern));
            break;
        case ATOMICRMW_REPLACE:
            MiscInstPatterns.push_back(std::make_unique<ATOMICRMWPattern>(pattern));
            break;
        case SIGNED_TO_UNSIGNED:
            MiscInstPatterns.push_back(std::make_unique<SignedToUnsigned>(pattern));
            break;
        case UNSIGNED_TO_SIGNED:
            MiscInstPatterns.push_back(std::make_unique<UnsignedToSigned>(pattern));
            break;
        case SWITCH_SHIFT:
            MiscInstPatterns.push_back(std::make_unique<ShiftSwitch>(pattern));
            break;
        case CALLOC:
            CallInstPatterns.push_back(std::make_unique<CallocPattern>(pattern));
            break;
        case DELETE_LOCAL_STORE:
            MiscInstPatterns.push_back(std::make_unique<UnInitLocalVariables>(pattern));
            break;
        case UNSIGNED_LESS_THAN:
            ICmpInstPatterns.push_back(std::make_unique<UnsignedLessThanPattern>(pattern));
            break;
        case UNSIGNED_GREATER_THAN:
            ICmpInstPatterns.push_back(std::make_unique<UnsignedGreaterThanPattern>(pattern));
            break;
        case UNSIGNED_LESS_THAN_EQUALTO:
            ICmpInstPatterns.push_back(std::make_unique<UnsignedLessThanEqualToPattern>(pattern));
            break;
        case UNSIGNED_GREATER_THAN_EQUALTO:
            ICmpInstPatterns.push_back(std::make_unique<UnsignedGreaterThanEqualToPattern>(pattern));
            break;
        case INET_ADDR_FAIL_WITHOUTCHECK:
            CallInstPatterns.push_back(std::make_unique<INetAddrFailPattern>(pattern));
            break;
        case COMPARE_EQUAL_TO:
            MiscInstPatterns.push_back(std::make_unique<CompareEqualToPattern>(pattern));
            break;
        case PRINTF:
            CallInstPatterns.push_back(std::make_unique<PrintfPattern>(pattern));
            break;
        case SPRINTF:
            CallInstPatterns.push_back(std::make_unique<SPrintfPattern>(pattern));
            break;
        case SNPRINTF:
            CallInstPatterns.push_back(std::make_unique<SNPrintfPattern>(pattern));
            break;
        case NEW_ARRAY:
            CallInstPatterns.push_back(std::make_unique<NewArrayPattern>(pattern));
            break;
        case SWITCH_PLUS_MINUS:
            MiscInstPatterns.push_back(std::make_unique<SwitchPlusMinus>(pattern));
            break;
        case REDIRECT_BRANCH:
            MiscInstPatterns.push_back(std::make_unique<RedirectBranch>(pattern));
            break;
        case DELETE_FUNCTION_ARGUMENT:
            MiscInstPatterns.push_back(std::make_unique<DeleteArgumentReturnPattern>(pattern));
            break;
        case DELETE_STORE_PATTERN:
            MiscInstPatterns.push_back(std::make_unique<DeleteStorePattern>(pattern));
            break;
        default:
            std::cerr << "Unknown Pattern Type: " << patternref["type"] << "\n" << std::flush;
    }
}

void populatePatternVectors(json* patternList) {
    if (patternList->is_array()) {
        for (auto pattern : *patternList) {
            populatePattern(&pattern);
        }
    }
}