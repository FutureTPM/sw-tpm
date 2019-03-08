#include "ldaa-params.h"
#include "ldaa-polynomial.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-sample-z.h"

const UINT32 LDAA_WS[65536] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1,
    4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4808194, 1, 4614810,
    4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194,
    4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1,
    4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810,
    4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194,
    4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1,
    4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810,
    4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194,
    4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1,
    4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810,
    4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194,
    4618904, 1, 4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904,
    1, 4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1,
    4614810, 4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 4614810,
    4808194, 4618904, 1, 4614810, 4808194, 4618904, 1, 2883726, 4614810,
    5178987, 4808194, 5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987,
    4808194, 5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194,
    5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923,
    4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904,
    3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904, 3145678,
    1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904, 3145678, 1,
    2883726, 4614810, 5178987, 4808194, 5178923, 4618904, 3145678, 1, 2883726,
    4614810, 5178987, 4808194, 5178923, 4618904, 3145678, 1, 2883726, 4614810,
    5178987, 4808194, 5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987,
    4808194, 5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194,
    5178923, 4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923,
    4618904, 3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904,
    3145678, 1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904, 3145678,
    1, 2883726, 4614810, 5178987, 4808194, 5178923, 4618904, 3145678, 1,
    6250525, 2883726, 7822959, 4614810, 601683, 5178987, 7375178, 4808194, 2682288,
    5178923, 1221177, 4618904, 4837932, 3145678, 4615550, 1, 6250525, 2883726,
    7822959, 4614810, 601683, 5178987, 7375178, 4808194, 2682288, 5178923, 1221177,
    4618904, 4837932, 3145678, 4615550, 1, 6250525, 2883726, 7822959, 4614810,
    601683, 5178987, 7375178, 4808194, 2682288, 5178923, 1221177, 4618904, 4837932,
    3145678, 4615550, 1, 6250525, 2883726, 7822959, 4614810, 601683, 5178987,
    7375178, 4808194, 2682288, 5178923, 1221177, 4618904, 4837932, 3145678, 4615550,
    1, 6250525, 2883726, 7822959, 4614810, 601683, 5178987, 7375178, 4808194,
    2682288, 5178923, 1221177, 4618904, 4837932, 3145678, 4615550, 1, 6250525,
    2883726, 7822959, 4614810, 601683, 5178987, 7375178, 4808194, 2682288, 5178923,
    1221177, 4618904, 4837932, 3145678, 4615550, 1, 6250525, 2883726, 7822959,
    4614810, 601683, 5178987, 7375178, 4808194, 2682288, 5178923, 1221177, 4618904,
    4837932, 3145678, 4615550, 1, 6250525, 2883726, 7822959, 4614810, 601683,
    5178987, 7375178, 4808194, 2682288, 5178923, 1221177, 4618904, 4837932, 3145678,
    4615550, 1, 7044481, 6250525, 4795319, 2883726, 4317364, 7822959, 2453983,
    4614810, 4855975, 601683, 6096684, 5178987, 1674615, 7375178, 6666122, 4808194,
    7703827, 2682288, 642628, 5178923, 3370349, 1221177, 1460718, 4618904, 7946292,
    4837932, 2815639, 3145678, 2663378, 4615550, 5152541, 1, 7044481, 6250525,
    4795319, 2883726, 4317364, 7822959, 2453983, 4614810, 4855975, 601683, 6096684,
    5178987, 1674615, 7375178, 6666122, 4808194, 7703827, 2682288, 642628, 5178923,
    3370349, 1221177, 1460718, 4618904, 7946292, 4837932, 2815639, 3145678, 2663378,
    4615550, 5152541, 1, 7044481, 6250525, 4795319, 2883726, 4317364, 7822959,
    2453983, 4614810, 4855975, 601683, 6096684, 5178987, 1674615, 7375178, 6666122,
    4808194, 7703827, 2682288, 642628, 5178923, 3370349, 1221177, 1460718, 4618904,
    7946292, 4837932, 2815639, 3145678, 2663378, 4615550, 5152541, 1, 7044481,
    6250525, 4795319, 2883726, 4317364, 7822959, 2453983, 4614810, 4855975, 601683,
    6096684, 5178987, 1674615, 7375178, 6666122, 4808194, 7703827, 2682288, 642628,
    5178923, 3370349, 1221177, 1460718, 4618904, 7946292, 4837932, 2815639, 3145678,
    2663378, 4615550, 5152541, 1, 3241972, 7044481, 7823561, 6250525, 2740543,
    4795319, 4623627, 2883726, 394148, 4317364, 1858416, 7822959, 7220542, 2453983,
    4805951, 4614810, 4018989, 4855975, 3192354, 601683, 5197539, 6096684, 6663429,
    5178987, 7284949, 1674615, 2917338, 7375178, 3110818, 6666122, 3415069, 4808194,
    2156050, 7703827, 4510100, 2682288, 4793971, 642628, 1935799, 5178923, 928749,
    3370349, 5034454, 1221177, 3704823, 1460718, 817536, 4618904, 2071829, 7946292,
    2897314, 4837932, 3602218, 2815639, 4430364, 3145678, 3506380, 2663378, 1853806,
    4615550, 6279007, 5152541, 1759347, 1, 3241972, 7044481, 7823561, 6250525,
    2740543, 4795319, 4623627, 2883726, 394148, 4317364, 1858416, 7822959, 7220542,
    2453983, 4805951, 4614810, 4018989, 4855975, 3192354, 601683, 5197539, 6096684,
    6663429, 5178987, 7284949, 1674615, 2917338, 7375178, 3110818, 6666122, 3415069,
    4808194, 2156050, 7703827, 4510100, 2682288, 4793971, 642628, 1935799, 5178923,
    928749, 3370349, 5034454, 1221177, 3704823, 1460718, 817536, 4618904, 2071829,
    7946292, 2897314, 4837932, 3602218, 2815639, 4430364, 3145678, 3506380, 2663378,
    1853806, 4615550, 6279007, 5152541, 1759347, 1, 6644104, 3241972, 6067579,
    7044481, 4183372, 7823561, 2461387, 6250525, 6852351, 2740543, 2236726, 4795319,
    4222329, 4623627, 7080401, 2883726, 5183169, 394148, 5697147, 4317364, 4528402,
    1858416, 3901472, 7822959, 169688, 7220542, 8031605, 2453983, 6352299, 4805951,
    5801164, 4614810, 5130263, 4018989, 7921254, 4855975, 3121440, 3192354, 7759253,
    601683, 1148858, 5197539, 6458164, 6096684, 5569126, 6663429, 4182915, 5178987,
    4213992, 7284949, 5604662, 1674615, 5307408, 2917338, 5454601, 7375178, 3334383,
    3110818, 1011223, 6666122, 4564692, 3415069, 2391089, 4808194, 8145010, 2156050,
    4912752, 7703827, 5157610, 4510100, 1317678, 2682288, 7897768, 4793971, 6635910,
    642628, 7270901, 1935799, 6018354, 5178923, 6392603, 928749, 2778788, 3370349,
    5744944, 5034454, 7153756, 1221177, 565603, 3704823, 327848, 1460718, 2508980,
    817536, 1787943, 4618904, 3258457, 2071829, 653275, 7946292, 274060, 2897314,
    3035980, 4837932, 5418153, 3602218, 3818627, 2815639, 2983781, 4430364, 3482206,
    3145678, 4892034, 3506380, 7023969, 2663378, 7102792, 1853806, 5006167, 4615550,
    2462444, 6279007, 6026202, 5152541, 6442847, 1759347, 2254727};

const UINT32 LDAA_WSINV[65536] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223,
    1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1, 3572223, 1,
    3572223, 1, 3572223, 1, 3572223, 1, 3761513, 3572223, 3765607, 1, 3761513,
    3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223,
    3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1,
    3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513,
    3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223,
    3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1,
    3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223,
    3765607, 1, 3761513, 3572223, 3765607,
    1, 3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1,
    3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513,
    3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223,
    3765607, 1, 3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607,
    1, 3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1,
    3761513, 3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 3761513,
    3572223, 3765607, 1, 3761513, 3572223, 3765607, 1, 5234739, 3761513,
    3201494, 3572223, 3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494,
    3572223, 3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223,
    3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430,
    3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607,
    5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691,
    1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691, 1,
    5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691, 1, 5234739,
    3761513, 3201494, 3572223, 3201430, 3765607, 5496691, 1, 5234739, 3761513,
    3201494, 3572223, 3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494,
    3572223, 3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223,
    3201430, 3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430,
    3765607, 5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607,
    5496691, 1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691,
    1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691, 1,
    3764867, 5234739, 3542485, 3761513, 7159240, 3201494, 5698129, 3572223, 1005239,
    3201430, 7778734, 3765607, 557458, 5496691, 2129892, 1, 3764867, 5234739,
    3542485, 3761513, 7159240, 3201494, 5698129, 3572223, 1005239, 3201430, 7778734,
    3765607, 557458, 5496691, 2129892, 1, 3764867, 5234739, 3542485, 3761513,
    7159240, 3201494, 5698129, 3572223, 1005239, 3201430, 7778734, 3765607, 557458,
    5496691, 2129892, 1, 3764867, 5234739, 3542485, 3761513, 7159240, 3201494,
    5698129, 3572223, 1005239, 3201430, 7778734, 3765607, 557458, 5496691, 2129892,
    1, 3764867, 5234739, 3542485, 3761513, 7159240, 3201494, 5698129, 3572223,
    1005239, 3201430, 7778734, 3765607, 557458, 5496691, 2129892, 1, 3764867,
    5234739, 3542485, 3761513, 7159240, 3201494, 5698129, 3572223, 1005239, 3201430,
    7778734, 3765607, 557458, 5496691, 2129892, 1, 3764867, 5234739, 3542485,
    3761513, 7159240, 3201494, 5698129, 3572223, 1005239, 3201430, 7778734, 3765607,
    557458, 5496691, 2129892, 1, 3764867, 5234739, 3542485, 3761513, 7159240,
    3201494, 5698129, 3572223, 1005239, 3201430, 7778734, 3765607, 557458, 5496691,
    2129892, 1, 3227876, 3764867, 5717039, 5234739, 5564778, 3542485, 434125,
    3761513, 6919699, 7159240, 5010068, 3201494, 7737789, 5698129, 676590, 3572223,
    1714295, 1005239, 6705802, 3201430, 2283733, 7778734, 3524442, 3765607, 5926434,
    557458, 4063053, 5496691, 3585098, 2129892, 1335936, 1, 3227876, 3764867,
    5717039, 5234739, 5564778, 3542485, 434125, 3761513, 6919699, 7159240, 5010068,
    3201494, 7737789, 5698129, 676590, 3572223, 1714295, 1005239, 6705802, 3201430,
    2283733, 7778734, 3524442, 3765607, 5926434, 557458, 4063053, 5496691, 3585098,
    2129892, 1335936, 1, 3227876, 3764867, 5717039, 5234739, 5564778, 3542485,
    434125, 3761513, 6919699, 7159240, 5010068, 3201494, 7737789, 5698129, 676590,
    3572223, 1714295, 1005239, 6705802, 3201430, 2283733, 7778734, 3524442, 3765607,
    5926434, 557458, 4063053, 5496691, 3585098, 2129892, 1335936, 1, 3227876,
    3764867, 5717039, 5234739, 5564778, 3542485, 434125, 3761513, 6919699, 7159240,
    5010068, 3201494, 7737789, 5698129, 676590, 3572223, 1714295, 1005239, 6705802,
    3201430, 2283733, 7778734, 3524442, 3765607, 5926434, 557458, 4063053, 5496691,
    3585098, 2129892, 1335936, 1, 6621070, 3227876, 2101410, 3764867, 6526611,
    5717039, 4874037, 5234739, 3950053, 5564778, 4778199, 3542485, 5483103, 434125,
    6308588, 3761513, 7562881, 6919699, 4675594, 7159240, 3345963, 5010068, 7451668,
    3201494, 6444618, 7737789, 3586446, 5698129, 3870317, 676590, 6224367, 3572223,
    4965348, 1714295, 5269599, 1005239, 5463079, 6705802, 1095468, 3201430, 1716988,
    2283733, 3182878, 7778734, 5188063, 3524442, 4361428, 3765607, 3574466, 5926434,
    1159875, 557458, 6522001, 4063053, 7986269, 5496691, 3756790, 3585098, 5639874,
    2129892, 556856, 1335936, 5138445, 1, 6621070, 3227876, 2101410, 3764867,
    6526611, 5717039, 4874037, 5234739, 3950053, 5564778, 4778199, 3542485, 5483103,
    434125, 6308588, 3761513, 7562881, 6919699, 4675594, 7159240, 3345963, 5010068,
    7451668, 3201494, 6444618, 7737789, 3586446, 5698129, 3870317, 676590, 6224367,
    3572223, 4965348, 1714295, 5269599, 1005239, 5463079, 6705802, 1095468, 3201430,
    1716988, 2283733, 3182878, 7778734, 5188063, 3524442, 4361428, 3765607, 3574466,
    5926434, 1159875, 557458, 6522001, 4063053, 7986269, 5496691, 3756790, 3585098,
    5639874, 2129892, 556856, 1335936, 5138445, 1, 6125690, 6621070, 1937570,
    3227876, 2354215, 2101410, 5917973, 3764867, 3374250, 6526611, 1277625, 5717039,
    1356448, 4874037, 3488383, 5234739, 4898211, 3950053, 5396636, 5564778, 4561790,
    4778199, 2962264, 3542485, 5344437, 5483103, 8106357, 434125, 7727142, 6308588,
    5121960, 3761513, 6592474, 7562881, 5871437, 6919699, 8052569, 4675594, 7814814,
    7159240, 1226661, 3345963, 2635473, 5010068, 5601629, 7451668, 1987814, 3201494,
    2362063, 6444618, 1109516, 7737789, 1744507, 3586446, 482649, 5698129, 7062739,
    3870317, 3222807, 676590, 3467665, 6224367, 235407, 3572223, 5989328, 4965348,
    3815725, 1714295, 7369194, 5269599, 5046034, 1005239, 2925816, 5463079, 3073009,
    6705802, 2775755, 1095468, 4166425, 3201430, 4197502, 1716988, 2811291, 2283733,
    1922253, 3182878, 7231559, 7778734, 621164, 5188063, 5258977, 3524442, 459163,
    4361428, 3250154, 3765607, 2579253, 3574466, 2028118, 5926434, 348812, 1159875,
    8210729, 557458, 4478945, 6522001, 3852015, 4063053, 2683270, 7986269, 3197248,
    5496691, 1300016, 3756790, 4158088, 3585098, 6143691, 5639874, 1528066, 2129892,
    5919030, 556856, 4197045, 1335936, 2312838, 5138445, 1736313};

const UINT32 LDAA_PSIS[LDAA_N] = {
    1, 1921994, 6644104, 7826699, 3241972, 1182243, 6067579, 5732423, 7044481,
    6607829, 4183372, 781875, 7823561, 5925040, 2461387, 507927, 6250525, 1310261,
    6852351, 214880, 2740543, 5607817, 2236726, 4399818, 4795319, 1239911, 4222329,
    5256655, 4623627, 5926272, 7080401, 6757063, 2883726, 6341273, 5183169, 140244,
    394148, 2296397, 5697147, 4357667, 4317364, 2387513, 4528402, 3974485, 1858416,
    4969849, 3901472, 1393159, 7822959, 5382198, 169688, 7009900, 7220542, 1935420,
    8031605, 2028038, 2453983, 12417, 6352299, 3014420, 4805951, 4423473, 5801164,
    1179613, 4614810, 4908348, 5130263, 3105558, 4018989, 7743490, 7921254, 8041997,
    4855975, 1727088, 3121440, 7648983, 3192354, 4829411, 7759253, 724804, 601683,
    613238, 1148858, 770441, 5197539, 5720009, 6458164, 6764887, 6096684, 6084318,
    5569126, 6187330, 6663429, 8352605, 4182915, 2374402, 5178987, 7561656, 4213992,
    4949981, 7284949, 4663471, 5604662, 5767564, 1674615, 268456, 5307408, 3531229,
    2917338, 3768948, 5454601, 1476985, 7375178, 8291116, 3334383, 11879, 3110818,
    6924527, 1011223, 3369273, 6666122, 5184741, 4564692, 2926054, 3415069, 6783595,
    2391089, 5637006, 4808194, 7921677, 8145010, 7872272, 2156050, 87208, 4912752,
    5370669, 7703827, 4146264, 5157610, 1900052, 4510100, 250446, 1317678, 7192532,
    2682288, 2218467, 7897768, 5016875, 4793971, 8321269, 6635910, 5811406, 642628,
    4541938, 7270901, 6195333, 1935799, 7371052, 6018354, 2105286, 5178923, 1879878,
    6392603, 6866265, 928749, 4423672, 2778788, 7630840, 3370349, 4768667, 5744944,
    3773731, 5034454, 1685153, 7153756, 2491325, 1221177, 8238582, 565603, 3020393,
    3704823, 1753, 327848, 6715099, 1460718, 1254190, 2508980, 1716814, 817536,
    4620952, 1787943, 586241, 4618904, 4340221, 3258457, 7277073, 2071829, 3965306,
    653275, 3033742, 7946292, 2192938, 274060, 7325939, 2897314, 635956, 3035980,
    1834526, 4837932, 1354892, 5418153, 545376, 3602218, 1780227, 3818627, 1723229,
    2815639, 3747250, 2983781, 6022044, 4430364, 822541, 3482206, 2033807, 3145678,
    6201452, 4892034, 860144, 3506380, 3284915, 7023969, 4148469, 2663378, 3180456,
    7102792, 303005, 1853806, 2678278, 5006167, 6386371, 4615550, 2513018, 2462444,
    3994671, 6279007, 2659525, 6026202, 1163598, 5152541, 5737437, 6442847, 7987710,
    1759347, 6400920, 2254727, 7852436};

const UINT32 LDAA_PSISINV[LDAA_N] = {
    8347681, 4814255, 4410553, 4950869, 3757768, 8283743, 3084753, 7212245, 929217,
    2548863, 7112909, 6438604, 3085393, 1522988, 7716078, 3983976, 4106707, 6358574,
    2828477, 185954, 3593719, 5138369, 2329247, 5487225, 6864157, 8004116, 3147955,
    5846913, 6664448, 7853281, 4236571, 3511264, 6731329, 4673304, 3063582, 422355,
    899302, 5083293, 3294681, 5812371, 4932138, 3037717, 4273500, 91254, 1360841,
    3140526, 5511220, 4577748, 1421486, 974914, 2476077, 1699788, 5291915, 7926232,
    4581970, 1366346, 1671232, 4636662, 7166633, 3978303, 679363, 528086, 2900776,
    8265255, 4957830, 30446, 1269720, 4957822, 4187015, 2546702, 5882680, 1500957,
    7785463, 7142954, 5498368, 7103706, 8071321, 3425482, 3238655, 8020875, 1861182,
    6177373, 2983768, 5263914, 6985839, 1131019, 1548887, 5055453, 3555059, 8088721,
    5357850, 8101249, 7754805, 2886683, 858901, 2284177, 1387418, 6473505, 1613291,
    1411591, 5983127, 4329688, 7991919, 7904371, 2223538, 6720916, 4360703, 7987816,
    3745914, 1388051, 5468798, 7422407, 5751059, 6911937, 1500709, 2552430, 4827311,
    647298, 7640078, 2864572, 591891, 1452141, 3647242, 5499308, 580826, 493025,
    3700088, 394624, 46690, 4626493, 1594724, 3476254, 936004, 7517851, 6922202,
    7476292, 4491529, 1852791, 748978, 7796856, 5291081, 3371762, 7810880, 1407997,
    2393655, 3955287, 273317, 3782654, 7125053, 7220863, 503044, 5498600, 3889043,
    4560511, 1745851, 5710584, 6944312, 7215321, 7578292, 5993887, 3482522, 56197,
    4272077, 3011821, 137651, 2136407, 3317318, 7243626, 1416569, 2821607, 1677045,
    6557593, 7410770, 4481823, 6084409, 3860453, 2714738, 2223217, 4847355, 7412208,
    1100554, 7008362, 1035359, 3659686, 5447944, 394154, 3308130, 35224, 1457421,
    708061, 732888, 1944987, 5023318, 7230049, 6655484, 1586785, 2043595, 642945,
    5573043, 4222896, 7290543, 188494, 3798739, 1956600, 2001427, 3508106, 7070314,
    1746720, 3603138, 223710, 1032312, 3941643, 3659173, 2767035, 571559, 1856626,
    5875616, 1128738, 4004274, 2511702, 5367165, 6939485, 6297802, 4983838, 4637248,
    6488070, 6814167, 4167059, 342035, 6755819, 3944563, 3366965, 5971957, 6595486,
    1759007, 4462927, 2051663, 3141817, 8320914, 1729890, 924928, 750944, 6635794,
    5738392, 6549376, 1666482, 2471595, 6946957, 4195427, 2301864, 4002827, 1141142,
    7974921, 329523, 4426143, 6605165};

UINT32 ldaa_reduce(UINT64 x)
{
  /* Input x is 0 <= x < 2^46 */
  /* 2^23 = 2^13 - 1 mod 8380417 */
  UINT32 x0 = x & ((1ULL<<23)-1);
  UINT32 x1 = (x >> 23) & ((1ULL<<10)-1);
  UINT32 x2 = (x >> 33) & ((1ULL<<10)-1);
  UINT32 x3 = (x >> 43);

  UINT32 z0 = x0;
  UINT32 z1 = x1 | (x2<<10) | (x3<<20);
  UINT32 z2 = x2 | (x3<<10);
  UINT32 z3 = x2<<13;
  UINT32 z4 = (x3<<13)-x3;
  UINT32 z5 = (x1<<13);

  UINT32 z = z0 - z1 - z2 + z3 + z4 + z5;

  while (z > (LDAA_Q<<2)) z += LDAA_Q; /* overflow due to subs */
  while (z >= LDAA_Q) z -= LDAA_Q;

  return z;
}

static void bit_swap(UINT32 *xs)
{
    const UINT64 logn = 8;
    UINT8 j;
    UINT16 i;

    for (i = 0; i < LDAA_N; i++) {
        UINT8 itarget = 0;
        for (j = 0; j < logn; j++) {
            UINT64 bit = (i >> j) & 1;
            itarget |= bit << (logn - 1 - j);
        }

        if (itarget > i) {
            UINT32 tmp = xs[i];
            xs[i] = xs[itarget];
            xs[itarget] = tmp;
        }
    }
}

static void ntt_plain(UINT32 *xs, const UINT32 *ws)
{
    UINT8 N, i, j;
    UINT16 h = 0;

    bit_swap(xs);

    for (N = LDAA_N/2; N > 0; N /= 2) {
        UINT16 k = LDAA_N / N;
        /* UINT32 wN = powm(w, N, LDAA_Q); */

        for (i = 0; i < N; i++) {
            /* UINT32 wi = 1; */
            for (j = 0; j < k/2; j++) {
                UINT32 wi = ws[h++];
                UINT32 yek = xs[(UINT8)(i * k + j)];
                UINT32 yok = xs[(UINT8)(i * k + k/2 + j)];
                yok = ldaa_reduce((UINT64)yok * wi);

                xs[(UINT8)(i * k + j)] = yek + yok;
                if (xs[(UINT8)(i * k + j)] >= LDAA_Q)
                    xs[(UINT8)(i * k + j)] -= LDAA_Q;

                xs[(UINT8)(i * k + k/2 + j)] = (yek < yok ? LDAA_Q : 0) + yek - yok;

                /* wi = reduce((UINT64)wi * wN); */
            }
        }
    }
}

void ldaa_poly_sample_z(ldaa_poly_t *this)
{
    size_t i;

    for (i = 0; i < LDAA_N; i++) {
        INT32 x = ldaa_sample_z(0, LDAA_S);
        this->coeffs[i] = (x < 0 ? LDAA_Q : 0) + x;
    }
}

void ldaa_poly_add(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b)
{
    size_t i;

    for (i = 0; i < LDAA_N; i++) {
        out->coeffs[i] = a->coeffs[i] + b->coeffs[i];
        if (out->coeffs[i] >= LDAA_Q) {
            out->coeffs[i] -= LDAA_Q;
        }
    }
}

void ldaa_poly_mul(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b)
{
    size_t i;
    UINT32 b1[LDAA_N];
    MemoryCopy(b1, b->coeffs, LDAA_N * sizeof(UINT32));
    MemoryCopy(out->coeffs, a->coeffs, LDAA_N * sizeof(UINT32));

    ldaa_poly_ntt(out->coeffs);
    ldaa_poly_ntt(b1);

    for (i = 0; i < LDAA_N; i++) {
        out->coeffs[i] = ldaa_reduce((UINT64)out->coeffs[i] * b1[i]);
    }

    ldaa_poly_invntt(out->coeffs);
}

void ldaa_poly_ntt(UINT32 *xs)
{
    size_t i;
    for (i = 0; i < LDAA_N; i++) {
        xs[i] = ldaa_reduce((UINT64)xs[i] * LDAA_PSIS[i]);
    }

    ntt_plain(xs, LDAA_WS);
}

void ldaa_poly_invntt(UINT32 *xs)
{
    size_t i;

    ntt_plain(xs, LDAA_WSINV);

    for (i = 0; i < LDAA_N; i++) {
        xs[i] = ldaa_reduce((UINT64)xs[i] * LDAA_PSISINV[i]);
    }
}

static UINT32 ceillog2(UINT32 q)
{
  size_t i = 0;

  while ((1ULL << i) < q) i++;

  return i;
}

void ldaa_poly_from_hash(
        // OUT: Resulting polynomial from the Hash
        ldaa_poly_t *out,
        // IN: Hash digest to convert
        BYTE *digest
        ) {
    size_t bits_consumed = 0;
    size_t j, k;
    UINT32 pi;
    UINT32 logq = ceillog2(LDAA_Q);
    UINT32 mask = (1ULL << logq)-1;

    for (size_t i = 0; i < LDAA_N; i++) {
        do {
            if (bits_consumed + logq >= (SHA256_DIGEST_SIZE * 8)) return;

            pi = digest[bits_consumed / 8] >> (bits_consumed % 8);
            k = 8 - (bits_consumed % 8);
            j = 1;
            while (k < logq) {
                pi += digest[bits_consumed / 8 + j] << k;
                k += 8;
                j++;
            }

            if (k > logq) pi &= mask;

            bits_consumed += logq;
        } while (pi >= LDAA_Q);

        out->coeffs[i] = pi;
    }
}

