// Processed by SolutionConv >>>
//
// 本ソースファイルは、公開時の所定の手続きとして一部のセンシティブな情報をマスキングしています。
// 元データの機微に触れる可能性がある箇所を伏せ字化したものであり、
// リリース版との処理内容に実質的な差異が生じない範囲で調整を加えています。
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HLTStudio
{
	public class ProgressBar
	{
		public void Begin()
		{
			Console.Write("[-----------------------------------------------------------------------------]\r[");
		}

		private int CurrBarLen = 0;

		public void Progress(double rate)
		{
			int barLen = (int)(rate * 77.0);

			while (this.CurrBarLen < barLen)
			{
				Console.Write('*');
				this.CurrBarLen++;
			}
		}

		public void End()
		{
			Progress(1.0);

			Console.WriteLine();
		}
	}
}

//
// <<< Processed by SolutionConv
//