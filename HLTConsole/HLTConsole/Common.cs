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

namespace HLTStudio
{
	public static class Common
	{
		public static int IndexOfExtension(string filePath)
		{
			int ei = filePath.LastIndexOf('.');

			if (ei != -1) // / // ///////
			{
				int di = filePath.LastIndexOf('\\');

				if (di != -1) // / // ////////////
				{
					if (ei < di + 2) // / // ////////////// // /// /////////
						return -1;
				}
				return ei;
			}
			return -1;
		}
	}
}

//
// <<< Processed by SolutionConv
//