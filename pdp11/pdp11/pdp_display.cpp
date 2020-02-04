#include "pdp_display.hpp"


pdp_display_controller::pdp_display_controller():
    m_pdp11(nullptr),
    m_raw_pixels{},
    m_small_rgb{},
    m_big_rgb(nullptr)
{}


void pdp_display_controller::set_controller(pdp11 *the_pdp11, v_rgb *dest)
{
    m_pdp11 = the_pdp11;
    m_big_rgb = dest;
}


void pdp_display_controller::process_buff()
{
    get_pixels_from_pdp(m_pdp11, m_raw_pixels);
    pdp_to_windows(m_raw_pixels, m_small_rgb, m_pdp11->get_video_adapter()->shift_register);
    enlarge_window(m_small_rgb, m_big_rgb);
}


void pdp_display_controller::unzip_font(uint8_t zipped_font[128][8])
{
    FILE *o_file = solver.fopen("..\\res\\font.txt", "w");

    //bool unzipped_font[128][64] = {};
    //uint8_t current_char[8];
    uint8_t current_str;
    uint8_t current_col;
    int current_bool;


    fprintf(o_file, "uint8_t unz_font[128][64] = \n{\n");
    for(int i = 0; i < 128; i++)
    {
        fprintf(o_file, "\t//%x\n", i);
        fprintf(o_file, "\t{\n");

        for(int j = 0; j < 8; j++)
        {
            
            current_str = zipped_font[i][j];

            for(int k = 0; k < 8; k++)
            {
                current_bool = current_str % 2;
                current_str >>= 1;
                current_col = font_arr[current_bool];

                if(k == 0)
                    fprintf(o_file, "\t\t");

                if(j != 7 || k != 7)
                    fprintf(o_file, "0x%02x, ", current_col);
                else
                    fprintf(o_file, "0x%02x", current_col);

                if(k == 7)
                    fprintf(o_file, "\n");
            }
        }

        if(i != 127)
            fprintf(o_file, "\t},\n");
        else
            fprintf(o_file, "\t}\n");
    }

    fprintf(o_file, "};\n");
    solver.fclose(o_file);
}


void pdp_display_controller::_8bit_to_24bit(uint8_t src, v_rgb *dest)
{
    assert(dest);

    uint8_t red = 0xe0;
    uint8_t green = 0x1c;
    uint8_t blue = 0x03;

    dest->a = 0xff;
    dest->r = static_cast<uint8_t>(((src & red) >> 5) * 255 / 7);
    dest->g = static_cast<uint8_t>(((src & green) >> 2) * 255 / 7);
    dest->b = static_cast<uint8_t>((src & blue) * 255 / 3);
}


void pdp_display_controller::pdp_to_windows(const uint8_t *src, v_rgb *dest, uint16_t shift_register)
{
    assert(shift_register <= 128 * 128);

    for(uint16_t i = 0; i < shift_register; i++)
    {
        _8bit_to_24bit(0, &dest[i]);
    }

    for(uint16_t i = shift_register; i < 128 * 128; i++)
    {
        _8bit_to_24bit(src[i], &dest[i]);
    }
}


void pdp_display_controller::enlarge_window(v_rgb *src, v_rgb *dest)
{
    unsigned long n1, n2;
    for(unsigned long i = 0; i < 128; i++)
    {
        for(unsigned long j = 0; j < 128; j++)
        {
            n2 = i * 128 + j;
            assert(n2 < 128 * 128);
            for(unsigned long k = 0; k < 4; k++)
            {
                for(unsigned long n = 0; n < 4; n++)
                {
                    n1 = (4 * i + k) * 512 + (4 * j + n);
                    assert(n1 < 512 * 512);

                    dest[n1] = src[n2];
                }
            }
        }
    }
}


void pdp_display_controller::get_pixels_from_pdp(pdp11 *the_pdp11, uint8_t *dest)
{
    const uint8_t *pdp_vram = the_pdp11->getVRAM();
    uint16_t mode = the_pdp11->get_video_adapter()->mode_register;

    if(mode == display_pixel_mode)
    {
        for(int i = 0; i < 128 * 128; i++)
        {
            dest[i] = pdp_vram[i];
        }
    }
    else if(mode == display_text_mode)
    {
        text_to_pixels(pdp_vram, dest);
    }
    else
    {
        assert(false);
    }
}


void pdp_display_controller::text_to_pixels(const uint8_t *res, uint8_t *dest)
{
    uint8_t current_col;
    uint8_t current_char;
    uint8_t *current_char_arr;
    int x, y;
    int current_pos_base;
    int current_pos;

    //DBG_PRINTF("text_to_pixels start\n");
    for(int i = 0; i < 16 * 16; i++)
    {
        current_char = res[i];
        assert(current_char < 128);
        current_char_arr = unz_font[current_char];
        
        x = i % 16;
        y = i / 16;
        current_pos_base = 8 * x + 16*8*8*y;
        
        //DBG_PRINTF("current_char = %d\n", current_char);

        for(int j = 0; j < 8; j++)
        {
            for(int k = 0; k < 8; k++)
            {
                current_pos = current_pos_base + 16*8*j + k;
                current_col = current_char_arr[8 * j + k];
                dest[current_pos] = current_col;
            }
        }
    }

    //DBG_PRINTF("text_to_pixels end\n\n");
}