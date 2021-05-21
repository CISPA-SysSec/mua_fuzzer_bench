#include "pattern_list.h"

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
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanSquaredPattern>());

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