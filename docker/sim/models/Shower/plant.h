// Flow model, native vector-input stepping contract. Scenario p0 is hot-pipe
// volume in litres, not the old fixed delay in seconds.
#define TOKEN "{7A3E5C10-9B2D-4F61-8E47-2C1D5B9F0A63}"
#define VR_P0 vr_hot_volume
#define VR_P1 vr_hot_temperature
#define VR_P2 vr_flush_time
#define NIN 2
#define VR_INS {vr_u_hot, vr_u_cold}
#define NOUT 7
// T_head, hot/cold positions, hot/cold flows (L/s), total/hot drawn litres.
#define VR_O {99, 1, 3, vr_hot_flow, vr_cold_flow, 101, 103}
#define NX SHOWER_NX
#define VR_X {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 95, 97, 99, 101, 103}
#define VR_DX {2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104}
