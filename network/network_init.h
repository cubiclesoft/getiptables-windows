// Cross-platform network initialization wrapper.
// (C) 2021 CubicleSoft.  All Rights Reserved.

#ifndef CUBICLESOFT_NETWORK_INIT
#define CUBICLESOFT_NETWORK_INIT

namespace CubicleSoft
{
	namespace Network
	{
		class Init
		{
		public:
			Init();
			~Init();

			inline bool Started()  { return MxStarted; }

		private:
			bool MxStarted;
		};
	}
}

#endif
