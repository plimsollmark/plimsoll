// What sim/shim_env.c needs to step and linearize this plant: the instantiation
// token, which three value references are the scenario parameters, which one is
// the input the controller sets each tick, which are the observations it gets
// back, and the state and derivative value references for the Jacobian.
#define TOKEN "{7A3E5C10-9B2D-4F61-8E47-2C1D5B9F0A63}"   /* Shower */
#define VR_P0 18  /* D, pipe delay (s) */
#define VR_P1 19  /* T_hot, hot supply temperature (C) */
#define VR_P2 20  /* t_flush, when the toilet is flushed (s) */
#define VR_IN 17  /* u, commanded hot fraction */
#define NOUT 2
#define VR_O {1, 3}  /* T_head, a */
#define NX 8
#define VR_X  {1, 3, 5, 7, 9, 11, 13, 15}   /* T_head, a, T1..T6 */
#define VR_DX {2, 4, 6, 8, 10, 12, 14, 16}  /* their derivatives */
