module tiny_tb;
    logic [7:0] a;
    logic [7:0] b;
    logic [8:0] y;

    tiny_top dut (.a(a), .b(b), .y(y));

    initial begin
        a = 8'd7;
        b = 8'd11;
        #1;
        if (y !== 9'd18) $fatal(1, "AOI_IC_PACK_MISMATCH");
        $display("AOI_IC_PACK_PASS y=%0d", y);
        $finish;
    end
endmodule
