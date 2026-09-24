// What sim/shim_env.c needs to step and linearize this plant.
#define TOKEN "{A7D2E4B6-8C1F-4E3A-9B5D-6F0C2A8E4D71}"   /* Rocket */
#define VR_P0 10  /* T_target, ordered Earth date of the return (years) */
#define VR_P1 11  /* fuel_budget, rapidity */
#define VR_P2 12  /* a_max */
#define VR_IN 9   /* a, proper acceleration */
#define NOUT 6
#define VR_O {3, 13, 5, 0, 7, 10}   /* x, beta, t (Earth), tau (own clock), fuel, T_target */
#define NX 4
#define VR_X  {1, 3, 5, 7}   /* eta, x, t, fuel */
#define VR_DX {2, 4, 6, 8}
