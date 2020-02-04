#pragma once
#include "pdp11.hpp"
#include "gui_defines.hpp"


extern uint8_t unz_font[128][64];
extern uint8_t font8x8_basic[128][8];


const uint8_t font_arr[2] = {0, 255};


class pdp_display_controller
{
public:
	pdp_display_controller();

	void set_controller(pdp11 *the_pdp11, v_rgb *dest);
	void process_buff();

	void unzip_font(uint8_t zipped_font[128][8]);

private:
	void _8bit_to_24bit(uint8_t src, v_rgb *dest);
	void pdp_to_windows(const uint8_t *src, v_rgb *dest, uint16_t shift_register);
	void enlarge_window(v_rgb *src, v_rgb *dest);
	void get_pixels_from_pdp(pdp11 *the_pdp11, uint8_t *dest);
	void text_to_pixels(const uint8_t *res, uint8_t *dest);

	pdp11 *m_pdp11;
	uint8_t m_raw_pixels[128 * 128];
	v_rgb m_small_rgb[128 * 128];
	v_rgb *m_big_rgb;
};
