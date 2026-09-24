// What sim/shim_env.c needs to step and linearize this plant. Two inputs.
#define TOKEN "{5E1A7C93-2B4D-4F6E-8A0B-9C3D1E5F7A2B}"   /* BlackHole */
#define VR_P0 15  /* r_target (gravitational radii) */
#define VR_P1 16  /* v0, initial radial velocity */
#define VR_P2 17  /* a_max, thrust limit per component */
#define NIN 2
#define VR_INS {13, 14}   /* a_r, a_phi */
#define VR_IN 13
#define NOUT 6
#define VR_O {1, 3, 18, 9, 11, 15}   /* r, dr/dtau, dphi/dtau, t, fuel, r_target */
#define NX 6
#define VR_X  {1, 3, 5, 7, 9, 11}   /* r, v, phi, L, t, fuel */
#define VR_DX {2, 4, 6, 8, 10, 12}
