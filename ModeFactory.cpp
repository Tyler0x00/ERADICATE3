#include "ModeFactory.hpp"

#include "hexadecimal.hpp"

mode ModeFactory::benchmark() {
	mode r;
	r.function = ModeFunction::Benchmark;
	return r;
}

mode ModeFactory::zerobytes() {
	mode r;
	r.function = ModeFunction::ZeroBytes;
	return r;
}

mode ModeFactory::zeros() {
	return range(0, 0);
}

mode ModeFactory::matching(const std::string strHex) {
	mode r;
	r.function = ModeFunction::Matching;

	std::fill( r.data1, r.data1 + sizeof(r.data1), cl_uchar(0) );
	std::fill( r.data2, r.data2 + sizeof(r.data2), cl_uchar(0) );

	auto index = 0;
	
	for( size_t i = 0; i < strHex.size(); i += 2 ) {
		const auto indexHi = hexValueNoException(strHex[i]);
		const auto indexLo = i + 1 < strHex.size() ? hexValueNoException(strHex[i+1]) : std::string::npos;

		const auto valHi = (indexHi == std::string::npos) ? 0 : indexHi << 4;
		const auto valLo = (indexLo == std::string::npos) ? 0 : indexLo;

		const auto maskHi = (indexHi == std::string::npos) ? 0 : 0xF << 4;
		const auto maskLo = (indexLo == std::string::npos) ? 0 : 0xF;

		r.data1[index] = maskHi | maskLo;
		r.data2[index] = valHi | valLo;

		++index;
	}

	return r;
}

mode ModeFactory::trailing(const std::string strHex) {
	mode r;
	r.function = ModeFunction::Matching;

	std::fill( r.data1, r.data1 + sizeof(r.data1), cl_uchar(0) );
	std::fill( r.data2, r.data2 + sizeof(r.data2), cl_uchar(0) );

	auto index = 0;
	
	for( size_t i = 0; i < strHex.size(); i += 2 ) {
		const auto indexHi = hexValueNoException(strHex[i]);
		const auto indexLo = i + 1 < strHex.size() ? hexValueNoException(strHex[i+1]) : std::string::npos;

		const auto valHi = (indexHi == std::string::npos) ? 0 : indexHi << 4;
		const auto valLo = (indexLo == std::string::npos) ? 0 : indexLo;

		const auto maskHi = (indexHi == std::string::npos) ? 0 : 0xF << 4;
		const auto maskLo = (indexLo == std::string::npos) ? 0 : 0xF;

		r.data1[20 - strHex.size()/2 + index] = maskHi | maskLo;
		r.data2[20 - strHex.size()/2 + index] = valHi | valLo;

		++index;
	}

	return r;
}

mode ModeFactory::leading(const char charLeading) {
	mode r;
	r.function = ModeFunction::Leading;
	r.data1[0] = static_cast<cl_uchar>(hexValue(charLeading));
	return r;
}

mode ModeFactory::leading_any() {
	mode r;
	r.function = ModeFunction::LeadingAny;
	return r;
}

// Combined "leading-any-pair" scoring, carrying two thresholds to the kernel:
//   data1[0] = minPair (P): the pair rule scores run1+run2 only when a leading
//              run of one nibble AND the following run of a different nibble are
//              each >= P.
//   data2[0] = minRun (T): a single leading run of >= T identical nibbles also
//              scores (its length). T == 0 disables the pure-run rule.
mode ModeFactory::leading_any_pair(const cl_uchar minRun, const cl_uchar minPair) {
	mode r;
	r.function = ModeFunction::LeadingAnyPair;
	r.data1[0] = minPair;
	r.data2[0] = minRun;
	return r;
}

mode ModeFactory::range(const cl_uchar min, const cl_uchar max) {
	mode r;
	r.function = ModeFunction::Range;
	r.data1[0] = min;
	r.data2[0] = max;
	return r;
}

mode ModeFactory::letters() {
	return range(10, 15);
}

mode ModeFactory::numbers() {
	return range(0, 9);
}

mode ModeFactory::leadingRange(const cl_uchar min, const cl_uchar max) {
	mode r;
	r.function = ModeFunction::LeadingRange;
	r.data1[0] = min;
	r.data2[0] = max;
	return r;
}

mode ModeFactory::mirror() {
	mode r;
	r.function = ModeFunction::Mirror;
	return r;
}

mode ModeFactory::doubles() {
	mode r;
	r.function = ModeFunction::Doubles;
	return r;
}
