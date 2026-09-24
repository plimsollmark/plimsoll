// What sim/shim_env.c needs to step and linearize this plant: the instantiation
// token, which three value references are the scenario parameters, which one is
// the input the controller sets each tick, which are the observations it gets
// back, and the state and derivative value references for the Jacobian.
#define TOKEN "{BFE341C2-CAE8-4202-9242-30BE8F255E82}"   /* CartPole */
#define VR_P0 5   /* theta, the initial angle from upright (rad); pi is hanging */
#define VR_P1 10  /* l, pole half-length (m) */
#define VR_P2 11  /* M, cart mass (kg) */
#define VR_IN 9   /* F, the force the controller applies (N) */
#define NOUT 4
#define VR_O {1, 3, 5, 7}   /* x, v, theta, omega */
#define NX 4
#define VR_X {1, 3, 5, 7}   /* the continuous states, in the model's order */
#define VR_DX {2, 4, 6, 8}  /* their derivatives */
