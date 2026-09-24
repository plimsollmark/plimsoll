// What sim/shim_env.c needs to step and linearize this plant.
#define TOKEN "{C3F8A1D5-6E2B-4C7A-9D0F-1B4E8A6C2F93}"   /* SatClock */
#define VR_P0 16  /* e, eccentricity */
#define VR_P1 17  /* y0, oscillator fractional frequency offset */
#define VR_P2 18  /* D, measurement delay (s) */
#define VR_IN 15  /* u, commanded fractional frequency correction */
#define NOUT 2
#define VR_O {13, 0}   /* the delayed measurement of the clock error (d6), and the time */
#define NX 7
#define VR_X  {1, 3, 5, 7, 9, 11, 13}
#define VR_DX {2, 4, 6, 8, 10, 12, 14}
