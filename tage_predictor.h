#ifndef TAGE_PREDICTOR_H
#define TAGE_PREDICTOR_H

#include <bitset>
#include <vector>
#include "branch_predictor.h"

#define GHIST_MAX_LEN 641  //length of global branch history
#define PATH_HIST_LEN 16
#define ALT_CTR_INIT 8
#define ALT_CTR_MAX 15

#define BIMODAL_BITS  14
#define BIMODAL_PRED_CTR_INIT 2
#define BIMODAL_PRED_CTR_MAX 3


#define NTABLE 12   // number of tagged componets 
#define TAGE_PRED_CTR_INIT 0
#define TAGE_PRED_CTR_MAX 7
#define TAGE_U_CTR_INIT 0 
#define TAGE_U_CTR_MAX 3
#define WEAK_NOT_TAKEN  3
#define WEAK_TAKEN  4

struct CompHist
{
  UInt32 comp;
  int comp_len;
  int orig_len;
};

struct TagEntry 
{
    UInt32 ctr;
    UInt32 tag;
    UInt32 u;
};

struct Prediction
{
  bool primary;
  bool alt;
  int primary_table;
  int alt_table;
};


class TagePredictor : public BranchPredictor
{

public:
  TagePredictor(String name, core_id_t core_id);
  ~TagePredictor();
  bool predict(IntPtr ip, IntPtr target);
  void update(bool predicted, bool actual, IntPtr ip, IntPtr target);

private:
  std::bitset<GHIST_MAX_LEN> ghist; 
  UInt32 phist;

  //base predictor 
  std::vector<UInt32>bimodal;     
  int bimodal_len;
  int bimodal_index;

  //tagged predictor
  std::vector< std::vector<TagEntry> >tage;
  std::vector<int>hist_len;
  std::vector<int>tage_tag_width;
  std::vector<int>tage_bits;
  std::vector<int>tage_len;    

  //history folding
  std::vector<CompHist>comp_index;
  std::vector<CompHist>comp_tag_1;
  std::vector<CompHist>comp_tag_2;

  std::vector<UInt32>tage_index;
  std::vector<UInt32>tage_tag;

  Prediction pred;
  UInt32 alt_ctr;

  UInt32 clock;
  bool clock_flip;

  void compressHistory(CompHist& comp_hist);
  void resetPrediction();
  void incrementCtr(UInt32& ctr, UInt32 max);
  void decrementCtr(UInt32& ctr);

  UInt32 getTag(IntPtr ip, int table, int tag_width);
  UInt32 getIndex(IntPtr ip, int table);

};


#endif