From msuinfo!uwm.edu!vixen.cso.uiuc.edu!howland.reston.ans.net!europa.eng.gtefsd.com!MathWorks.Com!news.kei.com!ddsw1!chinet!schneier Tue Mar 22 09:37:09 1994
Newsgroups: sci.crypt
Path: msuinfo!uwm.edu!vixen.cso.uiuc.edu!howland.reston.ans.net!europa.eng.gtefsd.com!MathWorks.Com!news.kei.com!ddsw1!chinet!schneier
From: schneier@chinet.chinet.com (Bruce Schneier)
Subject: BLOWFISH - Corrected code and Data File - from Apr 94 DDJ
Message-ID: <Cn0sEK.42x@chinet.chinet.com>
Organization: Chinet - Public Access UNIX
Distribution: usa
Date: Mon, 21 Mar 1994 15:01:31 GMT
Lines: 380

This is the corrected BLOWFISH code.  BLOWFISH is a secret key algorithm
that appeared in the Apr 94 Dr. Dobbs Journal.

This posting includes:
	blowfish.h
	blowfish.c
	blowfish.dat.uu

In deference to U.S. export laws, this code is being posted for "usa"
distribution only.

Bruce

**************************************************************************
* Bruce Schneier
* Counterpane Systems         For a good prime, call 391581 * 2^216193 - 1
* schneier@chinet.com
**************************************************************************

********************BLOWFISH.H********************

#define MAXKEYBYTES 56		/* 448 bits */
// #define little_endian 1		/* Eg: Intel */
#define big_endian 1		/* Eg: Motorola */

short opensubkeyfile(void);
unsigned long F(unsigned long x);
void Blowfish_encipher(unsigned long *xl, unsigned long *xr);
void Blowfish_decipher(unsigned long *xl, unsigned long *xr);
short InitializeBlowfish(char key[], short keybytes);

********************BLOWFISH.C********************

#ifdef little_endian   /* Eg: Intel */
   #include <dos.h>
   #include <graphics.h>
   #include <io.h>
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef little_endian   /* Eg: Intel */
   #include <alloc.h>
#endif

#include <ctype.h>

#ifdef little_endian   /* Eg: Intel */
   #include <dir.h>
   #include <bios.h>
#endif

#ifdef big_endian
   #include <Types.h>
#endif

#include "Blowfish.h"

#define N               16
#define noErr            0
#define DATAERROR         -1
#define KEYBYTES         8
#define subkeyfilename   "Blowfish.dat"

unsigned long P[N + 2];
unsigned long S[4][256];
FILE*         SubkeyFile;

short opensubkeyfile(void) /* read only */
{
   short error;

   error = noErr;

   if((SubkeyFile = fopen(subkeyfilename,"rb")) == NULL) {
      error = DATAERROR;
   }
 
   return error;
}

unsigned long F(unsigned long x)
{
   unsigned short a;
   unsigned short b;
   unsigned short c;
   unsigned short d;
   unsigned long  y;

   d = x & 0x00FF;
   x >>= 8;
   c = x & 0x00FF;
   x >>= 8;
   b = x & 0x00FF;
   x >>= 8;
   a = x & 0x00FF;
   //y = ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
   y = S[0][a] + S[1][b];
   y = y ^ S[2][c];
   y = y + S[3][d];

   return y;
}

void Blowfish_encipher(unsigned long *xl, unsigned long *xr)
{
   unsigned long  Xl;
   unsigned long  Xr;
   unsigned long  temp;
   short          i;

   Xl = *xl;
   Xr = *xr;

   for (i = 0; i < N; ++i) {
      Xl = Xl ^ P[i];
      Xr = F(Xl) ^ Xr;

      temp = Xl;
      Xl = Xr;
      Xr = temp;
   }

   temp = Xl;
   Xl = Xr;
   Xr = temp;

   Xr = Xr ^ P[N];
   Xl = Xl ^ P[N + 1];
  
   *xl = Xl;
   *xr = Xr;
}

void Blowfish_decipher(unsigned long *xl, unsigned long *xr)
{
   unsigned long  Xl;
   unsigned long  Xr;
   unsigned long  temp;
   short          i;

   Xl = *xl;
   Xr = *xr;

   for (i = N + 1; i > 1; --i) {
      Xl = Xl ^ P[i];
      Xr = F(Xl) ^ Xr;

      /* Exchange Xl and Xr */
      temp = Xl;
      Xl = Xr;
      Xr = temp;
   }

   /* Exchange Xl and Xr */
   temp = Xl;
   Xl = Xr;
   Xr = temp;

   Xr = Xr ^ P[1];
   Xl = Xl ^ P[0];

   *xl = Xl;
   *xr = Xr;
}

short InitializeBlowfish(char key[], short keybytes)
{
   short          i;
   short          j;
   short          k;
   short          error;
   short          numread;
   unsigned long  data;
   unsigned long  datal;
   unsigned long  datar;

   /* First, open the file containing the array initialization data */
   error = opensubkeyfile();
   if (error == noErr) {
      for (i = 0; i < N + 2; ++i) {
         numread = fread(&data, 4, 1, SubkeyFile);
   #ifdef little_endian      /* Eg: Intel   We want to process things in byte   */
                           /*   order, not as rearranged in a longword          */
         data = ((data & 0xFF000000) >> 24) |
                ((data & 0x00FF0000) >>  8) |
                ((data & 0x0000FF00) <<  8) |
                ((data & 0x000000FF) << 24);
   #endif

         if (numread != 1) {
            return DATAERROR;
         } else {
            P[i] = data;
         }
      }

      for (i = 0; i < 4; ++i) {
         for (j = 0; j < 256; ++j) {
             numread = fread(&data, 4, 1, SubkeyFile);

   #ifdef little_endian      /* Eg: Intel   We want to process things in byte   */
                           /*   order, not as rearranged in a longword          */
            data = ((data & 0xFF000000) >> 24) |
                   ((data & 0x00FF0000) >>  8) |
                   ((data & 0x0000FF00) <<  8) |
                   ((data & 0x000000FF) << 24);
   #endif

             if (numread != 1) {
               return DATAERROR;
            } else {
               S[i][j] = data;
            }
         }
      }

      fclose(SubkeyFile);

      j = 0;
      for (i = 0; i < N + 2; ++i) {
         data = 0x00000000;
         for (k = 0; k < 4; ++k) {
            data = (data << 8) | key[j];
            j = j + 1;
            if (j >= keybytes) {
               j = 0;
            }
         }
         P[i] = P[i] ^ data;
      }

        datal = 0x00000000;
      datar = 0x00000000;

      for (i = 0; i < N + 2; i += 2) {
         Blowfish_encipher(&datal, &datar);

         P[i] = datal;
         P[i + 1] = datar;
      }

      for (i = 0; i < 4; ++i) {
         for (j = 0; j < 256; j += 2) {

            Blowfish_encipher(&datal, &datar);
   
            S[i][j] = datal;
            S[i][j + 1] = datar;
         }
      }
   } else {
      printf("Unable to open subkey initialization file : %d\n", error);
   }

   return error;
}

********************BLOWFISH.DAT.UU********************


begin 0700 "Blowfish.dat"
Mic]JBhvCbmlsfxHN`WaSqjpinbhIGSgpbb[ZFnQn;hEejbgFnm`s=[YtyL\T
MZpQLPjPIM\E\tmT_AmvUMt<ieYhvU=Fi>?L;TsdkIIC?MzPO_wk;TaK?M[CA
MK^UJiGZvNGRpq?dL?YDDHyEgLYeL]P@a\NjeCOPvxVD@VgewsFFDvoZC]il]
M?@Vu=h]RCKyx<xOmvhhurNY[ujp=PEIyMyPPUsDJ\F`sQ=fPhRA@A?cjpwDx
MNmLX[XYYWka@nA@n;iXnB[`>BC[wew?aOsekiWBOk]IuxeQ@YEtE\ZIuJYqw
MriABx^@tpewjnvHJJQbVMlQ<maeaZlZAuhzO?gkID[oNeaeC;[PJjZGewwpx
Ml?;nwcXvFX>sgJ_vNCmLil]<>Cis@rBuAG<[CTBxzTNYK\r_ZaMFjbfsx=@i
MSoLAJyeh?jQ@w>R`lN^dwuWIAwvQWbxC`NMEfX@CBsZaTYzLQp]M;_nc]dhY
Mk@Md@Jrdh`qIRoajGA^;wBgfzdkVZvRzyPR<xzOsBoaJtzcrVepOzixoIRBK
MtsnC;N\k;amZn^rZn_ap?OLJFjgQyqTYKPeVyLIyoHiccHBl[Hxyqv^?MgVd
MI<l[BUZ^Xf]UVhwahgm`fDr?uLeJID[sJFhVoW<ff_[?<Dj;`CTWTm<DT`Hr
MrmLoZMmi\<b;aUmRRxbyfWLEUgGx]NC>]^o^taJV>tP[EVS@Ops`aKKaJt^V
Mpi]@QeY<GLhyzBqCzoMOKSYLt[tsn;kKnUkL;VW\tq^;litLSheeqj]>OpF^
MX]`dWCmj_vxoj`<ykDNSPlNHuTwh=`_rbU\YN=o[VUuYPkTzxchjUJd`QD`L
M<GEGGRw^^Q^CShZEZ?C;lBkXogtvW_UAzQtOta[hKpurJSh]M?K]hX=@tSe[
MrcX`WXj>we>[RF^lHaJguB[?eVG;UtjH]BA^_\nLySkfCd]u<VE;i[b[RECh
MX?^Cw;CPdz`p^CVx_rfcNdK\MvPMT=m;FEoD>;;XqvwrCDF\r_NwDng=\MJD
MRWXSxOLsp<[DQNCOhlKzmG=l`=a^GOXK\q^TE=OzszZpDyCJKxYQzYouHmbn
MT=bOQRw@CCQ;kXYUEk>o]Nk[\AhKyhBhNajpc?`<sZU>HfBoPQSqS_fqLZCa
MKr\OhAB^cA=WZGtM_HLbgZgEHlPoMv]TZaBL\];nB>jyMjAoXoTsXk=\QcNa
MTJVHVqy?HFz`Ew<eD\QSebdzeg?FKraE=[wZAL=tpOw[GswoZ\VOcgL^Bzcv
MpqOsKAY^rp`EcBT@<;m>hF@`NU>XXj\Dycz;\`FYgEuCDqUyWZzJ>lecB=Ez
MtW\@?uNB`NvYQxlF`WyBE<^Id<@yzdYSrDfSqRWj>QrIrAMq`ejztRDuU@]w
Mo[R;QNpKxjqV@>yT``BZ;[uwf^D?\I;LzRHmVqvVxVtAY[GYMO\Tar[eAuyD
Mt[`MwzF?CZdhND>y;HtgzDMZ<nFULREdVWtikLpyiBnM;JzPrz???ySNxkBo
M[;iF[jJl<vFze_]vyeiLPKf>XqDV`JuUbtPIHeDspnpxnCX_uiBzvTj=yvNo
MYmzy]S_vH=j<a^_HloumksCF\bu=PtS=hhzd<nLFxXkIQ@h>SeXizfL_oKKO
MRsRwfaqKzGbAzg\UAej@XHzWGeleJE`gmSXgAaQ_WJY<CGUd[e<v\KBPnMHW
M\e`lc?`<gPpb`ko_K@SUfCRU=khE@WIxW`DAO=fqd_E\Jr_VEcig<RkUqPdZ
MY>vam\kzWlBU=Crz\]VGJtqAq@_p`P[LRl<^Igt>p>hXSyD[Z@XOlHb[Hq@^
MLSenuhLXsVVYbf]bcpoVb@r_kk@rDbrw?gEv>;aROj^iK]Zz=Q_yDP@pLXNN
MdMSooRYudGh?kFMQie`zW>z?AlVg>EAgfgphVA>\GYJ\ZtM]CnQZ[cK;AqWZ
MxPEcyLqDP]kOgaAglAwybmUcnS<DPKHvdJempRIEQeepE``bdSKDWwg?^iXp
MltYu@zQWUE\qfyLdmu;QUZogzSPqfcMyijti\H_F[y?Q^_J>NK\LgAt\;H;C
MqwcJZv^QA@Y>bEH^jKmWg^<<sCTf^BEEWkFyYQTo@cZiUEiFRbtNslEXGabS
MzLxucKJtXNIXI?P\tQXjk?sR]TZGmATKoqDYi@\yPGE@tBnGbo<sdK;KK?YN
MZLl?yNn\qyvF>\BcLw\WTpfl_RCclMWOOFQzIvuxhxuHJY@b[LZEc]LOEsLJ
M[WVMvVXOAatAMB@IaVeP[mUg=vf?eq`sSj@PZVf]E@lT_AZJ`VooMwm<DdQP
MHCGuGIXkRZK>en[lAKQ@xBRGGjM<J[kSAfYDBQZOf;WPRJ`Cz;EEvKMppfAz
MlCPJMklQGNGuPbfX]YMtbQFgwZbyE?>y?Fh]?zCXmXBzE^lM=QgMDU\vzaja
McCvhj<?Fg]zvWM^A>eBZFu?UAjt;hGiCFXoc_QKbqI;mLPKKtRXPuh_yrnqM
MOcdHvnOR[Ssf_^K^jnUA[GP\<UUjemGHyk?CpAa=eb`^d^ae[NjVHZJKZMML
MsQwZRT_pQTkTpN]JN[uEsSL=p<TAa=@>>yZfAtWgYdMgzCVaxEcoxJgRvXTF
MqORh@ZcaQ[zC?QtDPVGk=iigAhHkuIjRApE;OPbMftB=efjQ=bnbc@axpHTJ
McewUZAVM]cXCoWaAlWkPDHVs?Dgvw^SQ;bh[VWS>mUGk[Gq@phwRI\YWlFZF
MaXbdf?ApGNCOVeuAVy<UJvFGJLtlaLizajO\@`OjWiYd>B[cqsrd_=uGapX>
MGLG;<]OsdevhSv=?VGGCyTm`Q<pTywd^nm@]joB>\vW_hat^h>>oLcUjYNn?
Mj]NcK??IouIHEhe`]_yliARtzrDTpqt@]WxbUo>\]fLNUjh`zmphigdShoqJ
Mp[?tMU``xz\>n?xNERqeqApAsWr_BXA`syw\gyzUDz]P]mWsyJ`Oq;^\b>Pc
MOy>e?ZQMTcgkAprvZR>Su?TYp=HEq^zKR@JzjeaXiuldj?pjkh;zZ;yM^VC<
MefkwrfD`z`[`Ib>AC>Yoo_ZBZh>MCkvlX`yZ]mzVJLX>?mlWw^Sn>jnypfLJ
MpBc^GCwy\XvY[CGwJSLrsHL=R?KWrVTxuBzCyCgJXY>RnF[Z=mU;pSiHp>?W
MRG@@^_Lj]t[x_KnwqtavKkIhEr=utSHZhhnmA_YKJ;?pEIukuzAGOjduFECl
MJrECF>g;lZxJrEx_lrwYwOq^gi`IlwS]^n@bab<O<hb[euPejbSCE<durnsf
M;rihPql_QP^fW`?YR>Yaaa\opd=YIeVh;A<RwUgKUyO`T?j\Px]adsuDiwMX
Mmf`JGfc?^nBCgVmLfPXrMlhbXsj>KVyoT<Kq@quKhYw@lSZrXsLDbVkNOKDB
MA;jBcNzZcyG><@RlkzkWjm`r>dvuMYs]ygThxN?l]?atrzmOAWUh^Ln=_r?S
MoHT>bD=CpyDN_WpZ;VZK]oC]mZ@rWfbAZ]WXFqOAsmMNzPWf>Utp;v<LmR=E
MUcO<Tn@d\rDmQ\P`_ZnUnp^rzp_MbVy[G_OnVWV<Higob]DuwJn[dR^htuNM
MigNt>;]Vn];KmSDNL\PqvwF`iNjw]bXQkvAbKz?fzBL[dGulSg@N\qQJdDhW
MMYiqYPzAN^yk^VmpfFLpfagj[?H]i;WxXNgcRtqbeEDjdAnfVpSL;MvKZBID
MKV=nVHzHw[Z_ZxADYlo^G;R`u_cWPhy@>gOXx`m@s=g]@T;Vna^P=TvNam<V
M_lRcpFLS\aZK<;b`px<\`eY?=ZawOKWHKBquqDjyOU@NxtYx]h_RW?VB]gsO
Mnh>iO<isyOGcRknn=kqU\Euf_mFY>NLFxxL=WXrdz@YYDu^uXDyNvxX@Me=P
MCmuuD<DbWDRYbZSANXheTafHxDAU=jF>MW\yMNbIW`EFkpFAQcifl^AzgPhi
M\kZlrIF@iqUN_A`zNsT=bZvDWZff\@\HzoeIWk?z@U<YaOZAXLZ;s\U_tE`q
Mw@fGaHoZH`jUQ`WFTb>z^hPG=S^fp<m@s`yAJ`zU\a=ZjlcUAN``xeBJlmQ]
MxAgFGM<CnnICt\k=ElkbeCr[R^YvDkRVWNO\?zgnvqUV;PwDbtM\`x@Y<@H]
M?ii\ih;C<E]RsyVYfLe;Mmn>NoSMueuXboREM=@]?mmmKp_dgEcOwKeAYOBB
MAqsy;edsof_uQ^=vXt[dmBJ_SMWfRc?wFChTDFnbdF<n^HY`x`c@nCGnm]oZ
M]<^KPG<WvLtMfURPyYYoHS=bTXhGpiF\F[[udxZ=OP]Se=xMgg[g`lq[MXP;
MzRfADdvR;Kf^zCyNMe=hJR^\EfYYQJmVTFuiPLAsc_CNqHW>?=uSbAUlTdWf
MjsF[VZFZqEbLEr;HOE[CajgZU?aJkufzx^^lXIJf[Bk`B<jXpRpN]Jt>`ZJ<
M\MbD@\aANIOIzDVoYqupNFq;UB@FHOFGnCKArZFuAN]uxNGgk^_s]UkWVC\d
M;VEW^@Iy@nrIex>PA@f;b>zMnS[ED^Fp_uJ>mm>wkobWVphKBUfvUzPZ`wVF
M?=gooMy\?rTHgY\ESZWRNiMzUKqRvHCUsn`IKgg@fzwFq[bL_>Vs^IOHT\rm
MjcMwSoCuyBEYdRXH>e\aD>UUxewWE@YdX]m>Cate;=rh]fVZ`ZeAipuD\kWc
MZYXuoiawHI<GfNRIn@<JfS]MFQYCh?wUGf;[iMSSfwtSVrBQu?WU`UxT@HJZ
MokLHtw<qP@Ky^jOltv?lKyi?s>@wts@PWhXWGuABDRcYD>IZDlk[oGOntrgn
Myg=oOCjHMNm^PRD]qDC>tVEDd^z`HJXhdmUMLBqIArW]bp<AyKnzq@IDq<c=
MvfS>SQP@RjY;OO?=fUBmplSr`w]KMnn[WziJ?CIy_Tt^mpIdOksmUwkJSJCZ
Myhr[CvxrKK\\;T?rF^qCub]=GJ[b=QOVsFmP=`XmC>=;dU?X<AyQKUm]wta`
MRPAnMnklmmifz@duKXsAL`pHEy@ZgpzXG[sn;Jah;S\[@Ct@JXhafAUkiWhG
M^fduxkgGDS_<NSIYjSqei;V@BcGAt<YYrR\RR;>@g[KiXaSh?KSgT?;o`qgc
MH>BJQQJpATGts[VzTmK>R]tjVC@cn<lJQIdVyXWYlwS@LrMo]YYyMToUNSKR
MUqG_i]EeGk^whBPuYOPJcYg\<yNterwZYymASKz<Z\jHyeDrNJCqMLdgwNle
Mz@PpTEaERPnDpNcL;@XvFmL[siB@OCiXZvr?gYtRXmnrW]n@mbNi<?h>fPIT
MptNCmhSeOGd@PWxRVm\UGXV;Fr\NY@MOqP_C\qWEsmItgMKxD<YB><_moGYO
MeABQyOTLgpvdC]ke]OLBF?tC\U>FlGxCDZ@Ulu;lSpjL\heBvGwKMvXvmI>h
MTGolWIyBDHfYr=alti`;<<yven;fQ[TR>Apjq>gpaLoR>YKiJEo]xJ@o`kLE
MO^hUO=kV<qiIa;hd`BjVR\]\Swz<jUlqoL`vpnosnjN]xbugK?bZnbb<]T;n
M=G>OH<t@=va@A<O^sHKHC=AZJOFPsoFJ?AEhPEPb^XJl`<mJYm;KX?FpUoAI
MIES>Hc\iirWbbnz?MTYAlLYWXEMwC]_CnLmRYK@ZRPh@`CEZ;L;[v__oUmUl
MOU[q]c_E@C[TZblMerKPYQCi<eF]Fb`?rIUBYZtINHGAihT[^hyvQqemcKQl
M[AxcsxHYhnqX@NFNC[WCJ]P?;zt>tEVRNNda^fYZ;yQHJr<h_mDIokPlLcRf
M^jBMkb\`pD[KRLMekxGl<?SuGg^q?PxBOfVjbkfcsrdRzhsj@NnJR_mWAOkZ
MkjMNo<YsvMgRbLxgQKCAsUZTnhYWtarFyvyE][yjp^rZncTaLNpp>xZRFf^p
MG@RDgWLW=RPrxcbebh<xQn?qOtaE_\ZcDOVjJC;qj[shR=bys[bWeoEHfoFE
MnyB@HwCfiHrHgHKI<OzXpEZV>BGtAEt;UQFOlLfiUqqua=RaUsYhpD[zMY;O
MqJaiCPmF?>[>`ZPjL\rw<SUseJBqljBoSixdq`KnZXDZ=RvXjPX>]ITPjERn
MY[Am[UHQLi;iZ_BmtrUXCGY``NZgXbKVPUBANPkHUZ_?G[cG>pZtjCL\fKKf
M_Z>OG?>v^sh;Nypa=jBH[rhvkl_QNYGzJmuqImwDr^S=X^RHc<ti`YoN\Gir
MosgtCCH<hDZVwFarPZpAb<lOar[CBnV??JFqQB^w=[u;HatlOjlZ[ftEWSfc
M@TnISBzsxJVk`sptbXWUSXd>G_uyeG\eyc@r]naxBEjPR[CIqn];eJmSQnVA
M??S^ZOukR[Zg<^orQsg<TewdyREr=T\Zu\IKPdy]nCLD=XpEMYD>FMVbwb;D
MtLCN_jS>gHrcnOmAhqTceSkal<RMLD?FaKZl<rLY\xBT[SDZG\WeQwuqzq_V
MFt\Y@IRPdpeE<SmcR^MAT]bTqolj[ZBN<WtJnAR=Mk<iemzKipRenWlHru^t
MC]jD[xYL]UgDPRb[==GjHknkIviBsHrPo^ZHaVYTHg_E@cG@cc;_VO@c<Qmx
MN>yQN=KdSARRvQcMs=ouL?SRMhafmouYi>Kd`jFLu>IRBsk?a@p=auTQ]pke
Mn<kCjXGyVUOlbIC`v_UOfRtfhBXAO@Y@ESLd[mujy[uoYCBF[vxuFaJqbEVr
MDHVL;\zwYSQCKtuNWU]e>Heetx=zylTPF?eIM?fjCgoNbUYwmH]L>?r[>EEy
kiJJTGLzjRoS[@`a
`
end


