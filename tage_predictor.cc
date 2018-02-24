#include "tage_predictor.h"

TagePredictor::TagePredictor(String name, core_id_t core_id):
  BranchPredictor(name, core_id)
{
  //initialize global branch history
  ghist.reset();
  phist = 0;

  //initialize tage variables
  hist_len = {640, 403, 254, 160, 101, 64, 40, 25, 16, 10, 6, 4};
  tage_tag_width = {15, 14, 13, 12, 12, 11, 10, 9, 8, 8, 7, 7};
  tage_bits = {9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 10, 10};

  for(int i=0; i<NTABLE; i++)
  {
    tage_len.push_back(1 << tage_bits[i]);
  }

  //initialize the bimodal table
  bimodal_len = (1 << BIMODAL_BITS);

  for(int i=0; i<bimodal_len; i++)
  {
    bimodal.push_back(BIMODAL_PRED_CTR_INIT);
  }

  //initialize tagged components
  for(int i=0; i<NTABLE; i++)
  {
    std::vector<TagEntry> vec;
    for(int j=0; j<tage_len[i]; j++)
    {
      vec.push_back({TAGE_PRED_CTR_INIT, 0, TAGE_U_CTR_INIT});
    }

    tage.push_back(vec);

    comp_index.push_back({0, tage_bits[i], hist_len[i]});
    comp_tag_1.push_back({0, tage_tag_width[i], hist_len[i]});
    comp_tag_2.push_back({0, tage_tag_width[i]-1, hist_len[i]});

    tage_index.push_back(0);
    tage_tag.push_back(0);
  }

  alt_ctr = ALT_CTR_INIT;
  clock = 0;
  clock_flip = false;
}

TagePredictor::~TagePredictor()
{

}

bool TagePredictor::predict(IntPtr ip, IntPtr target)
{
  bool bimodal_pred, final_pred;
  resetPrediction();

  for(int i=0; i<NTABLE; i++)
  {
    tage_tag[i] = getTag(ip, i, tage_tag_width[i]);
    tage_index[i] = getIndex(ip, i);
  }

  // find bimodal prediction
  bimodal_index = ip & (1 << (BIMODAL_BITS - 1));
  bimodal_pred = bimodal[bimodal_index] > BIMODAL_PRED_CTR_INIT / 2;   // prediction bit is MSB

  // find primary prediction
  for(int i=0; i<NTABLE; i++)
  {
    if(tage[i][tage_index[i]].tag == tage_tag[i])
    {
      pred.primary_table = i;
      break;
    }
  }

  // find alternate prediction 
  for(int i=pred.primary_table+1; i<NTABLE; i++)
  {
    if(tage[i][tage_index[i]].tag == tage_tag[i])
    {
      pred.alt_table = i;
      break;
    }
  }

  // no tag match, use bimodal table
  if(pred.primary_table == NTABLE)
  {
    final_pred = bimodal_pred;
  }
  else
  {
    if(pred.alt_table == NTABLE)
    {
      pred.alt = bimodal_pred;
    } 
    else
    {
      pred.alt = tage[pred.alt_table][tage_index[pred.alt_table]].ctr > TAGE_PRED_CTR_MAX / 2;
    }

    // whether to use primary prediction
    TagEntry& entry = tage[pred.primary_table][tage_index[pred.primary_table]];
    bool use_primary = entry.ctr != WEAK_NOT_TAKEN ||
                       entry.ctr != WEAK_TAKEN ||
                       entry.u != TAGE_U_CTR_INIT ||
                       alt_ctr < 8;

    pred.primary = entry.ctr > TAGE_PRED_CTR_MAX / 2;
    
    if(use_primary)
    {
      final_pred = pred.primary;
    }
    else
    {
      final_pred = pred.alt;
    }
  }

  return final_pred;
}

void TagePredictor::update(bool predicted, bool actual, IntPtr ip, IntPtr target)
{
  bool new_entry;

  updateCounters(predicted, actual);

  // update bimodal since default prediction is used
  if(pred.primary_table == NTABLE)
  {
    if(actual)
    {
      incrementCtr(bimodal[bimodal_index], BIMODAL_PRED_CTR_MAX);
    }
    else
    {
      decrementCtr(bimodal[bimodal_index]);
    }
  }
  else
  {
    TagEntry& entry = tage[pred.primary_table][tage_index[pred.primary_table]];

    //update useful counter
    if(predicted != pred.alt)
    {
      incrementCtr(entry.u, TAGE_U_CTR_MAX);
    }
    else
    {
      decrementCtr(entry.u);
    }

    //update prediction counter
    if(actual)
    {
      incrementCtr(entry.ctr, TAGE_PRED_CTR_MAX);
    }
    else
    {
      decrementCtr(entry.ctr);
    }

    new_entry = (entry.ctr == WEAK_TAKEN || entry.ctr == WEAK_NOT_TAKEN) &&
                entry.u == TAGE_U_CTR_INIT;

    // update the alt_ctr
    if(new_entry)
    {
      if(predicted != pred.alt)
      {
        if(pred.alt == actual)
        {
          incrementCtr(alt_ctr, ALT_CTR_MAX);
        }
        else
        {
          decrementCtr(alt_ctr);
        }
      }
    }
    

  }

  // new entry allocation
  if(pred.primary_table > 0 && predicted != actual)
  {
    bool empty_u_found;
    for(int i=0; i<pred.primary_table; i++)
    {
      if(tage[i][tage_index[i]].u == 0)
      {
        empty_u_found = true;
        break;
      }
    }

    if(!empty_u_found)
    {
      for(int i=0; i<pred.primary_table; i++)
      {
        decrementCtr(tage[i][tage_index[i]].u);
      }
    }

    else
    {
      //randomly select one table to allocate new entry
      srand(time(NULL));
      int randNum = rand() % 100;
      std::vector<int> candidates;
      int selected_table = 0;

      for (int i = 0; i < pred.primary_table; i++)
      {
        if (tage[i][tage_tag[i]].u == 0)
        {
            candidates.push_back(i);
        }
      }  

      if(candidates.size() == 1)
      {
          selected_table = candidates[0];
      }
      else if(candidates.size() > 1)
      {
        if(randNum > 33 && randNum <= 99)
        {
          selected_table = candidates[candidates.size()-1];
        }
        else
        {
          selected_table = candidates[candidates.size()-2];
        }   
      }

      TagEntry& entry = tage[selected_table][tage_index[selected_table]];

      if(actual)
      {
        entry.ctr = WEAK_TAKEN;
      } 
      else
      {
        entry.ctr = WEAK_NOT_TAKEN;
      }
      entry.tag = tage_tag[selected_table];
      entry.u = TAGE_U_CTR_INIT;

    }

  }
  

  // reset counter after 256k cycles
  clock++;
  if(clock == 256 * 1024)
  {
    
    if(!clock_flip)
    {
      // reset MSB of u ctr
      for(int i=0; i<NTABLE; i++)
      {
        for(int j=0; j<tage_len[i]; j++)
        {
          tage[i][j].u &= 1; 
        }
      }
    }
    else
    {
      // reset LSB of u ctr
      for(int i=0; i<NTABLE; i++)
      {
        for(int j=0; j<tage_len[i]; j++)
        {
          tage[i][j].u &= 2;
        }
      }
    }

    clock = 0;
    clock_flip = !clock_flip;
  }

  // update the global history and path history.
  ghist = (ghist << 1);
  phist = (phist << 1);
  if (actual) 
  {
    ghist.set(0,1);
    // phist += 1;
    
  }

  UInt32 pc = (UInt32) ip;
  if(pc & 1)
  {
    phist += 1;
  }

  phist &= ((1 << PATH_HIST_LEN) - 1);

  // history folding
  for(int i=0; i<NTABLE; i++)
  {
    compressHistory(comp_index[i]);
    compressHistory(comp_tag_1[i]);
    compressHistory(comp_tag_2[i]);
  }

}

void TagePredictor::resetPrediction()
{
  pred.primary = 0;
  pred.alt = 0;
  pred.primary_table = NTABLE;
  pred.alt_table = NTABLE;
}

void TagePredictor::incrementCtr(UInt32& ctr, UInt32 max)
{
  if(ctr < max)
  {
    ctr = ctr + 1; 
  }
}

void TagePredictor::decrementCtr(UInt32& ctr)
{
  if(ctr > 0)
  {
    ctr = ctr - 1;
  }
}

void TagePredictor::compressHistory(CompHist& comp_hist)
{
  comp_hist.comp = (comp_hist.comp << 1) | ghist[0];
  comp_hist.comp ^= ghist[comp_hist.orig_len] << (comp_hist.orig_len % comp_hist.comp_len);
  comp_hist.comp ^= (comp_hist.comp >> comp_hist.comp_len);
  comp_hist.comp &= (1 << comp_hist.comp_len) - 1;
}

UInt32 TagePredictor::getIndex(IntPtr ip, int table)
{
  UInt32 pc = (UInt32) ip;
  UInt32 index = pc ^ (pc >> (tage_bits[table] - table )) ^ comp_index[table].comp ^ (phist >> (tage_bits[table] - table));
  return (index & (tage_len[table] - 1));
}

UInt32 TagePredictor::getTag(IntPtr ip, int table, int tag_width)
{
  UInt32 pc = (UInt32) ip;
  UInt32 tag = (pc ^ comp_tag_1[table].comp ^ (comp_tag_2[table].comp << 1));
  return (tag & ((1 << tag_width) - 1));
}
