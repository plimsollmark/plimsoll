// What sim/shim_env.c needs to step and linearize this plant.
#define TOKEN "{2C9D7E41-5B3A-4F08-9A1C-6E2B8D4F7A15}"   /* Ship */
#define VR_P0 8   /* K, Nomoto gain (1/s) */
#define VR_P1 9   /* T, Nomoto time constant (s) */
#define VR_P2 10  /* wave, yaw-acceleration amplitude (rad/s^2) */
#define VR_IN 7   /* u, commanded rudder angle (rad) */
#define NOUT 3
#define VR_O {1, 3, 5}   /* psi, r, delta */
#define NX 3
#define VR_X  {1, 3, 5}  /* psi, r, delta */
#define VR_DX {2, 4, 6}  /* their derivatives */
