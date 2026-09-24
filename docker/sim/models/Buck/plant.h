// What sim/shim_env.c needs to step and linearize this plant.
#define TOKEN "{9F4B2A6C-1D7E-4B35-8C2A-3E6F9D1B5A70}"   /* Buck */
#define VR_P0 6   /* Vin, input voltage (V) */
#define VR_P1 7   /* R0, load resistance before the step (ohm) */
#define VR_P2 8   /* t_step, when the load halves (s) */
#define VR_IN 5   /* u, duty cycle */
#define NOUT 2
#define VR_O {1, 3}   /* v, i */
#define NX 2
#define VR_X  {1, 3}  /* v, i */
#define VR_DX {2, 4}  /* their derivatives */
